package jwt

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/nuominmin/timex"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	"github.com/spf13/cast"
)

const (
	HeaderAuthorizationKey   = "Authorization"
	AuthorizationValueBearer = "Bearer"
	ErrMissingToken          = "missing token"
	ErrInvalidToken          = "invalid token"
	contextKeyUserID         = "userID"
)

type Service struct {
	secret []byte
}

func NewService(secret []byte) *Service {
	return &Service{
		secret: secret,
	}
}

func (s *Service) NewSecret() ([]byte, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate jwt, error: %v", err)
	}
	return secret, nil
}

func (s *Service) GenerateJWT(userId uint64, extra interface{}) (string, error) {
	now := timex.Now()
	claims := jwt.MapClaims{
		contextKeyUserID: userId,
		"exp":            now.Add(time.Hour * 24 * 30).Unix(),
		"iat":            now.Unix(),
		"extra":          extra,
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
}

func (s *Service) Middleware(ignoredPaths ...string) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			var tokenString string

			if tr, ok := transport.FromServerContext(ctx); ok {
				operation := tr.Operation()

				// check if the request path is in the ignore list
				for i := 0; i < len(ignoredPaths); i++ {
					if operation == ignoredPaths[i] {
						// ignore this path, call the next handler
						return handler(ctx, req)
					}
				}

				authHeader := tr.RequestHeader().Get(HeaderAuthorizationKey)
				if authHeader == "" {
					return nil, NewAuthorizationError(ErrMissingToken)
				}

				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) != 2 || parts[0] != AuthorizationValueBearer {
					return nil, NewAuthorizationError(ErrInvalidToken)
				}

				tokenString = parts[1]
			} else {
				return nil, NewAuthorizationError(ErrMissingToken)
			}

			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, NewAuthorizationError(ErrInvalidToken)
				}
				return s.secret, nil
			})

			if err != nil || !token.Valid {
				return nil, NewAuthorizationError(ErrInvalidToken)
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				return nil, NewAuthorizationError(ErrInvalidToken)
			}

			return handler(s.NewContextWithUserId(ctx, cast.ToUint64(claims[contextKeyUserID])), req)
		}
	}
}

func (s *Service) NewContextWithUserId(ctx context.Context, userId uint64) context.Context {
	return context.WithValue(ctx, contextKeyUserID, userId)
}

func (s *Service) GetUserId(ctx context.Context) (uint64, error) {
	value := ctx.Value(contextKeyUserID)
	if userId, ok := value.(uint64); ok {
		return userId, nil
	}
	return 0, errors.New("failed to get user Id from context")
}

type AuthorizationError struct {
	Code    int
	Message string
}

func (e *AuthorizationError) Error() string {
	return fmt.Sprintf(`{"code": %d, "message": "%s"}`, e.Code, e.Message)
}

func NewAuthorizationError(format string, a ...any) *AuthorizationError {
	if format == "" {
		format = "Unauthorized"
	}
	return &AuthorizationError{
		Code:    401,
		Message: fmt.Sprintf(format, a...),
	}
}
