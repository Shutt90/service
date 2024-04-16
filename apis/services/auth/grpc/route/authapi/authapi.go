package authapi

import (
	"context"

	"github.com/ardanlabs/service/app/api/authsrv/gprc"
	"github.com/ardanlabs/service/app/api/errs"
	"github.com/ardanlabs/service/app/api/mid"
	"github.com/ardanlabs/service/app/domain/userapp"
	"github.com/ardanlabs/service/business/api/auth"
	"github.com/ardanlabs/service/business/domain/userbus"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

type api struct {
	userApp *userapp.Core
	auth    *auth.Auth
	gprc.UnimplementedAuthServer
}

func New(userBus *userbus.Core, auth *auth.Auth) *api {
	return &api{
		userApp: userapp.NewCoreWithAuth(userBus, auth),
		auth:    auth,
	}
}

func (api *api) Token(ctx context.Context, kid *gprc.Kid) (*gprc.TokenString, error) {
	token, err := api.userApp.Token(ctx, kid.Kid)
	if err != nil {
		return nil, err
	}

	ts := gprc.TokenString{
		Token: token.Token,
	}

	return &ts, nil
}

func (api *api) Authenticate(ctx context.Context, ap *gprc.AuthParams) (*gprc.AuthResp, error) {
	userID, err := mid.GetUserID(ctx)
	if err != nil {
		return nil, errs.New(errs.Unauthenticated, err)
	}

	claims := mid.GetClaims(ctx)

	resp := gprc.AuthResp{
		UserId: userID.String(),
		Claims: &gprc.Claims{
			Issuer:    claims.Issuer,
			Subject:   claims.Subject,
			Audience:  claims.Audience,
			ExpiresAt: timestamppb.New(claims.ExpiresAt.Time),
			NotBefore: timestamppb.New(claims.NotBefore.Time),
			IssuedAt:  timestamppb.New(claims.IssuedAt.Time),
			Id:        claims.ID,
			Roles:     []string{claims.Roles[0].Name()},
		},
	}

	return &resp, nil
}

func (api *api) Authorize(ctx context.Context, ai *gprc.AuthInfo) (*emptypb.Empty, error) {
	claims := auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ai.Claims.Issuer,
			Subject:   ai.Claims.Subject,
			Audience:  jwt.ClaimStrings(ai.Claims.Audience),
			ExpiresAt: jwt.NewNumericDate(ai.Claims.ExpiresAt.AsTime()),
			NotBefore: jwt.NewNumericDate(ai.Claims.NotBefore.AsTime()),
			IssuedAt:  jwt.NewNumericDate(ai.Claims.IssuedAt.AsTime()),
			ID:        ai.Claims.Id,
		},
		//Roles: ai.Claims.Roles,
	}

	userID, err := uuid.Parse(ai.UserId)
	if err != nil {
		return nil, errs.New(errs.Unauthenticated, err)
	}

	if err := api.auth.Authorize(ctx, claims, userID, ai.Rule); err != nil {
		return nil, errs.Newf(errs.Unauthenticated, "authorize: you are not authorized for that action, claims[%v] rule[%v]: %s", "auth.Claims.Roles", ai.Rule, err)
	}

	return &emptypb.Empty{}, nil
}
