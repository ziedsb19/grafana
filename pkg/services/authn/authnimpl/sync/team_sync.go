package sync

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/grafana/authlib/claims"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/team"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

func ProvideTeamSync(userService user.Service, teamService team.Service, accessControl accesscontrol.Service, cfg *setting.Cfg, tracer tracing.Tracer, teamPermissionsService accesscontrol.TeamPermissionsService) *TeamSync {
	return &TeamSync{userService, teamService, teamPermissionsService, accessControl, cfg, log.New("team.sync"), tracer}
}

type TeamSync struct {
	userService           user.Service
	teamService           team.Service
	teamPermissionService accesscontrol.TeamPermissionsService
	accessControl         accesscontrol.Service
	cfg                   *setting.Cfg
	log                   log.Logger
	tracer                tracing.Tracer
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
	orgId := id.SignedInUser().GetOrgID()

	ctxLogger.Debug("Start Custom Zied Syncing Teams", "userId", userID, "orgId", orgId, "extGroups", id.Groups)

	teams, err := s.teamService.GetUserTeamMemberships(ctx, orgId, userID, false)
	if err != nil {
		ctxLogger.Warn("Failed to sync teams, error retreiving teams", "type", id.GetIdentityType(), "err", err)
		return nil
	}

	for _, t := range teams {
		teamId := t.TeamID
		tm, err := s.teamService.GetTeamByID(ctx, &team.GetTeamByIDQuery{OrgID: t.OrgID, ID: teamId})
		if err != nil {
			ctxLogger.Warn("Failed to get team by id, error retreiving team ", "orgId", t.OrgID, "teamId", teamId, "err", err)
			return nil
		}
		if userIsNotMemberOfTeam(tm, teamMapping) {
			ctxLogger.Warn("Removing user from team membership", "userId", userID, "userName", id.Name, "teamId", teamId, "teamName", tm.Name)
			err := s.removeTeamMember(ctx, ctxLogger, orgId, teamId, userID)
			if err != nil {
				ctxLogger.Warn("Failed to remove user membership ", "orgId", tm.OrgID, "userId", userID, "teamId", teamId, "err", err)
				return nil
			}
		}
	}

	elevatedUser := elevatedTempUserWithPermissions(ctx, *id, orgId, accesscontrol.Permission{Action: accesscontrol.ActionTeamsRead, Scope: "*"})

	for _, tm := range teamMapping {
		var tmcId int64
		qr, err := s.teamService.SearchTeams(ctx, &team.SearchTeamsQuery{OrgID: orgId, Name: tm.teamName, SignedInUser: &elevatedUser})
		if err != nil {
			ctxLogger.Warn("error searching for team ", "orgId", orgId, "teamName", tm.teamName, "err", err)
			return nil
		}

		if qr.TotalCount == 0 {
			tmc, err := s.teamService.CreateTeam(ctx, tm.teamName, "", orgId)
			if err != nil {
				ctxLogger.Warn("error creating team ", "teamName", tm.teamName, "err", err)
				return nil
			}
			tmcId = tmc.ID
		} else {
			ctxLogger.Info("team already exist skip creation step ", "orgId", orgId, "teamName", tm.teamName)
			tmcId = qr.Teams[0].ID
		}

		err = s.addTeamMember(ctx, ctxLogger, orgId, tmcId, userID)
		if err != nil {
			ctxLogger.Warn("error adding team membership for user ", "orgId", orgId, "teamName", tm.teamName, "userID", userID, "err", err)
			return nil
		}

	}

	return nil
}

func elevatedTempUserWithPermissions(ctx context.Context, cloneId authn.Identity, orgId int64, permissions ...accesscontrol.Permission) authn.Identity {
	id := cloneId
	tempPermissions := make([]accesscontrol.Permission, 0)
	for _, acPerm := range permissions {
		tempPermissions = append(tempPermissions, acPerm)
	}
	id.Permissions[orgId] = accesscontrol.GroupScopesByActionContext(ctx, tempPermissions)
	return id

}

func (s *TeamSync) addTeamMember(ctx context.Context, ctxLogger *log.ConcreteLogger, orgId, teamId, userId int64) error {
	var err error

	isTeamMember, err := s.teamService.IsTeamMember(ctx, orgId, teamId, userId)
	if err != nil {
		ctxLogger.Warn("error checking user team membership ", "orgId", orgId, "teamName", teamId, "userID", userId, "err", err)
		return err
	}
	if isTeamMember {
		return nil
	}

	err = addOrUpdateTeamMember(
		ctx, s.teamPermissionService,
		userId, orgId, teamId, team.PermissionTypeMember.String(),
	)
	if err != nil {
		ctxLogger.Warn("error adding user team membership ", "orgId", orgId, "teamName", teamId, "userID", userId, "err", err)
		return err
	}

	return nil
}

func (s *TeamSync) removeTeamMember(ctx context.Context, ctxLogger *log.ConcreteLogger, orgId, teamId, userId int64) error {
	teamIDString := strconv.FormatInt(teamId, 10)
	if _, err := s.teamPermissionService.SetUserPermission(ctx, orgId, accesscontrol.User{ID: userId}, teamIDString, ""); err != nil {
		if errors.Is(err, team.ErrTeamNotFound) {
			ctxLogger.Warn("Team not found", "orgId", orgId, "teamName", teamId, "userID", userId, "err", err)
			return err
		}

		if errors.Is(err, team.ErrTeamMemberNotFound) {
			ctxLogger.Warn("Team member not found", "orgId", orgId, "teamName", teamId, "userID", userId, "err", err)
			return err
		}

		ctxLogger.Warn("Failed to remove Member from Team", "orgId", orgId, "teamName", teamId, "userID", userId, "err", err)

		return err
	}
	return nil
}

var addOrUpdateTeamMember = func(ctx context.Context, resourcePermissionService accesscontrol.TeamPermissionsService, userID, orgID, teamID int64, permission string) error {
	teamIDString := strconv.FormatInt(teamID, 10)
	if _, err := resourcePermissionService.SetUserPermission(ctx, orgID, accesscontrol.User{ID: userID}, teamIDString, permission); err != nil {
		return fmt.Errorf("failed setting permissions for user %d in team %d: %w", userID, teamID, err)
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
