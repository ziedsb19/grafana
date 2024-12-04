package sync

import (
	"context"
	"fmt"

	"github.com/grafana/authlib/claims"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/team"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

func ProvideTeamSync(userService user.Service, teamService team.Service, accessControl accesscontrol.Service, cfg *setting.Cfg, tracer tracing.Tracer) *TeamSync {
	return &TeamSync{userService, teamService, accessControl, cfg, log.New("team.sync"), tracer}
}

type TeamSync struct {
	userService   user.Service
	teamService   team.Service
	accessControl accesscontrol.Service
	cfg           *setting.Cfg
	log           log.Logger
	tracer        tracing.Tracer
}

type TeamMapping struct {
	teamName string
}

func (s *TeamSync) SyncTeamsHook(ctx context.Context, id *authn.Identity, _ *authn.Request) error {

	ctx, span := s.tracer.Start(ctx, "org.sync.SyncTeamsHook")
	defer span.End()

	ctxLogger := s.log.FromContext(ctx).New("id", id.ID, "login", id.Email)

	if !id.ClientParams.SyncTeams {
		return nil
	}

	id.Groups = append(id.Groups, "readonlyusers")

	teamMapping := make([]*TeamMapping, 0)
	for _, grp := range id.Groups {
		teamMapping = append(teamMapping, &TeamMapping{teamName: grp})
	}

	if !id.SignedInUser().IsIdentityType(claims.TypeUser) {
		ctxLogger.Warn("Failed to sync teams, invalid namespace for identity", "type", id.GetIdentityType())
		return nil
	}

	userID, err := id.SignedInUser().GetInternalID()
	if err != nil {
		ctxLogger.Warn("Failed to sync teams, invalid ID for identity", "type", id.GetIdentityType(), "err", err)
		return nil
	}

	ctxLogger.Debug("Start Custom Zied Syncing Teams", "extGroups", id.Groups)

	teams, err := s.teamService.GetUserTeamMemberships(ctx, id.SignedInUser().GetOrgID(), userID, false)
	if err != nil {
		ctxLogger.Warn("Failed to sync teams, error retreiving teams", "type", id.GetIdentityType(), "err", err)
		return nil
	}

	for _, t := range teams {
		teamId := t.TeamID
		tm, err := s.teamService.GetTeamByID(ctx, &team.GetTeamByIDQuery{OrgID: t.OrgID, ID: teamId})
		if err != nil {
			ctxLogger.Warn("Failed to get team by id, error retreiving team ", "id", teamId, "err", err)
			return nil
		}
		if userIsNotMemberOfTeam(tm, teamMapping) {
			ctxLogger.Warn("Removing user from team membership", "userId", userID, "userName", id.Name, "teamId", teamId, "teamName", tm.Name)
			err := s.teamService.RemoveUserTeamMemberships(ctx, tm.OrgID, userID, teamId)
			if err != nil {
				ctxLogger.Warn("Failed to remove user membership ", "orgId", tm.OrgID, "userId", userID, "teamId", teamId, "err", err)
				return nil
			}
		}
	}

	for _, tm := range teamMapping {
		tmc, err := s.teamService.CreateTeam(ctx, tm.teamName, "", id.SignedInUser().GetOrgID())
		fmt.Println(tmc, id.SignedInUser().GetOrgID())
		if err != nil {
			ctxLogger.Warn("error creating team ", "teamName", tm.teamName, "err", err)
			continue
		}
		err = s.teamService.AddUserTeamMembership(ctx, tmc.OrgID, tmc.ID, userID, false)
		if err != nil {
			ctxLogger.Warn("error adding team membership ", "teamName", tm.teamName, "userID", userID, "err", err)
			return nil
		}

	}

	return nil
}

func userIsNotMemberOfTeam(team *team.TeamDTO, teamMapping []*TeamMapping) bool {
	for _, tm := range teamMapping {
		if team.Name == tm.teamName {
			return false
		}
	}
	return true
}
