package token

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	"github.com/google/uuid"
	"strings"
)

const (
	HeaderAuthorizationKey   = "Authorization"
	AuthorizationValueBearer = "Bearer"
	ErrMissingToken          = "missing token"
	ErrInvalidToken          = "invalid token"
	contextKeyToken          = "token"
)

type Service struct {
}

func NewService() *Service {
	return &Service{}
}

func (s *Service) GenerateToken() string {
	return strings.ReplaceAll(uuid.New().String(), "-", "")
}

func (s *Service) Middleware(ignoredPaths []string, m ...middleware.Middleware) middleware.Middleware {
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

			// 将 token 信息传递给 handler
			ctx = s.newContextWithToken(ctx, tokenString)

			for i := 0; i < len(m); i++ {
				handler = m[i](handler) // 链式调用中间件
			}

			return handler(ctx, req)
		}
	}
}

func (s *Service) newContextWithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, contextKeyToken, token)
}

func (s *Service) GetToken(ctx context.Context) (string, error) {
	if token, ok := ctx.Value(contextKeyToken).(string); ok {
		return token, nil
	}
	return "", errors.New("failed to token from context")
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
