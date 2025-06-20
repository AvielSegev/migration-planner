// Package server provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.3.0 DO NOT EDIT.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	externalRef0 "github.com/kubev2v/migration-planner/api/v1alpha1"
	"github.com/oapi-codegen/runtime"
	strictnethttp "github.com/oapi-codegen/runtime/strictmiddleware/nethttp"
)

// ServerInterface represents all server handlers.
type ServerInterface interface {

	// (GET /api/v1/image/bytoken/{token}/{name})
	GetImageByToken(w http.ResponseWriter, r *http.Request, token string, name string)

	// (HEAD /api/v1/image/bytoken/{token}/{name})
	HeadImageByToken(w http.ResponseWriter, r *http.Request, token string, name string)

	// (GET /health)
	Health(w http.ResponseWriter, r *http.Request)
}

// Unimplemented server implementation that returns http.StatusNotImplemented for each endpoint.

type Unimplemented struct{}

// (GET /api/v1/image/bytoken/{token}/{name})
func (_ Unimplemented) GetImageByToken(w http.ResponseWriter, r *http.Request, token string, name string) {
	w.WriteHeader(http.StatusNotImplemented)
}

// (HEAD /api/v1/image/bytoken/{token}/{name})
func (_ Unimplemented) HeadImageByToken(w http.ResponseWriter, r *http.Request, token string, name string) {
	w.WriteHeader(http.StatusNotImplemented)
}

// (GET /health)
func (_ Unimplemented) Health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}

// ServerInterfaceWrapper converts contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler            ServerInterface
	HandlerMiddlewares []MiddlewareFunc
	ErrorHandlerFunc   func(w http.ResponseWriter, r *http.Request, err error)
}

type MiddlewareFunc func(http.Handler) http.Handler

// GetImageByToken operation middleware
func (siw *ServerInterfaceWrapper) GetImageByToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// ------------- Path parameter "token" -------------
	var token string

	err = runtime.BindStyledParameterWithOptions("simple", "token", chi.URLParam(r, "token"), &token, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "token", Err: err})
		return
	}

	// ------------- Path parameter "name" -------------
	var name string

	err = runtime.BindStyledParameterWithOptions("simple", "name", chi.URLParam(r, "name"), &name, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "name", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetImageByToken(w, r, token, name)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// HeadImageByToken operation middleware
func (siw *ServerInterfaceWrapper) HeadImageByToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// ------------- Path parameter "token" -------------
	var token string

	err = runtime.BindStyledParameterWithOptions("simple", "token", chi.URLParam(r, "token"), &token, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "token", Err: err})
		return
	}

	// ------------- Path parameter "name" -------------
	var name string

	err = runtime.BindStyledParameterWithOptions("simple", "name", chi.URLParam(r, "name"), &name, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "name", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.HeadImageByToken(w, r, token, name)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// Health operation middleware
func (siw *ServerInterfaceWrapper) Health(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.Health(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

type UnescapedCookieParamError struct {
	ParamName string
	Err       error
}

func (e *UnescapedCookieParamError) Error() string {
	return fmt.Sprintf("error unescaping cookie parameter '%s'", e.ParamName)
}

func (e *UnescapedCookieParamError) Unwrap() error {
	return e.Err
}

type UnmarshalingParamError struct {
	ParamName string
	Err       error
}

func (e *UnmarshalingParamError) Error() string {
	return fmt.Sprintf("Error unmarshaling parameter %s as JSON: %s", e.ParamName, e.Err.Error())
}

func (e *UnmarshalingParamError) Unwrap() error {
	return e.Err
}

type RequiredParamError struct {
	ParamName string
}

func (e *RequiredParamError) Error() string {
	return fmt.Sprintf("Query argument %s is required, but not found", e.ParamName)
}

type RequiredHeaderError struct {
	ParamName string
	Err       error
}

func (e *RequiredHeaderError) Error() string {
	return fmt.Sprintf("Header parameter %s is required, but not found", e.ParamName)
}

func (e *RequiredHeaderError) Unwrap() error {
	return e.Err
}

type InvalidParamFormatError struct {
	ParamName string
	Err       error
}

func (e *InvalidParamFormatError) Error() string {
	return fmt.Sprintf("Invalid format for parameter %s: %s", e.ParamName, e.Err.Error())
}

func (e *InvalidParamFormatError) Unwrap() error {
	return e.Err
}

type TooManyValuesForParamError struct {
	ParamName string
	Count     int
}

func (e *TooManyValuesForParamError) Error() string {
	return fmt.Sprintf("Expected one value for %s, got %d", e.ParamName, e.Count)
}

// Handler creates http.Handler with routing matching OpenAPI spec.
func Handler(si ServerInterface) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{})
}

type ChiServerOptions struct {
	BaseURL          string
	BaseRouter       chi.Router
	Middlewares      []MiddlewareFunc
	ErrorHandlerFunc func(w http.ResponseWriter, r *http.Request, err error)
}

// HandlerFromMux creates http.Handler with routing matching OpenAPI spec based on the provided mux.
func HandlerFromMux(si ServerInterface, r chi.Router) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{
		BaseRouter: r,
	})
}

func HandlerFromMuxWithBaseURL(si ServerInterface, r chi.Router, baseURL string) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{
		BaseURL:    baseURL,
		BaseRouter: r,
	})
}

// HandlerWithOptions creates http.Handler with additional options
func HandlerWithOptions(si ServerInterface, options ChiServerOptions) http.Handler {
	r := options.BaseRouter

	if r == nil {
		r = chi.NewRouter()
	}
	if options.ErrorHandlerFunc == nil {
		options.ErrorHandlerFunc = func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	}
	wrapper := ServerInterfaceWrapper{
		Handler:            si,
		HandlerMiddlewares: options.Middlewares,
		ErrorHandlerFunc:   options.ErrorHandlerFunc,
	}

	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/api/v1/image/bytoken/{token}/{name}", wrapper.GetImageByToken)
	})
	r.Group(func(r chi.Router) {
		r.Head(options.BaseURL+"/api/v1/image/bytoken/{token}/{name}", wrapper.HeadImageByToken)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/health", wrapper.Health)
	})

	return r
}

type GetImageByTokenRequestObject struct {
	Token string `json:"token"`
	Name  string `json:"name"`
}

type GetImageByTokenResponseObject interface {
	VisitGetImageByTokenResponse(w http.ResponseWriter) error
}

type GetImageByToken200ApplicationovfResponse struct {
	Body          io.Reader
	ContentLength int64
}

func (response GetImageByToken200ApplicationovfResponse) VisitGetImageByTokenResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/ovf")
	if response.ContentLength != 0 {
		w.Header().Set("Content-Length", fmt.Sprint(response.ContentLength))
	}
	w.WriteHeader(200)

	if closer, ok := response.Body.(io.ReadCloser); ok {
		defer closer.Close()
	}
	_, err := io.Copy(w, response.Body)
	return err
}

type GetImageByToken400JSONResponse externalRef0.Error

func (response GetImageByToken400JSONResponse) VisitGetImageByTokenResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)

	return json.NewEncoder(w).Encode(response)
}

type GetImageByToken401JSONResponse externalRef0.Error

func (response GetImageByToken401JSONResponse) VisitGetImageByTokenResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(401)

	return json.NewEncoder(w).Encode(response)
}

type GetImageByToken404JSONResponse externalRef0.Error

func (response GetImageByToken404JSONResponse) VisitGetImageByTokenResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(404)

	return json.NewEncoder(w).Encode(response)
}

type GetImageByToken500JSONResponse externalRef0.Error

func (response GetImageByToken500JSONResponse) VisitGetImageByTokenResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(500)

	return json.NewEncoder(w).Encode(response)
}

type HeadImageByTokenRequestObject struct {
	Token string `json:"token"`
	Name  string `json:"name"`
}

type HeadImageByTokenResponseObject interface {
	VisitHeadImageByTokenResponse(w http.ResponseWriter) error
}

type HeadImageByToken200Response struct {
}

func (response HeadImageByToken200Response) VisitHeadImageByTokenResponse(w http.ResponseWriter) error {
	w.WriteHeader(200)
	return nil
}

type HeadImageByToken400JSONResponse externalRef0.Error

func (response HeadImageByToken400JSONResponse) VisitHeadImageByTokenResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)

	return json.NewEncoder(w).Encode(response)
}

type HeadImageByToken401JSONResponse externalRef0.Error

func (response HeadImageByToken401JSONResponse) VisitHeadImageByTokenResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(401)

	return json.NewEncoder(w).Encode(response)
}

type HeadImageByToken404JSONResponse externalRef0.Error

func (response HeadImageByToken404JSONResponse) VisitHeadImageByTokenResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(404)

	return json.NewEncoder(w).Encode(response)
}

type HeadImageByToken500JSONResponse externalRef0.Error

func (response HeadImageByToken500JSONResponse) VisitHeadImageByTokenResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(500)

	return json.NewEncoder(w).Encode(response)
}

type HealthRequestObject struct {
}

type HealthResponseObject interface {
	VisitHealthResponse(w http.ResponseWriter) error
}

type Health200Response struct {
}

func (response Health200Response) VisitHealthResponse(w http.ResponseWriter) error {
	w.WriteHeader(200)
	return nil
}

// StrictServerInterface represents all server handlers.
type StrictServerInterface interface {

	// (GET /api/v1/image/bytoken/{token}/{name})
	GetImageByToken(ctx context.Context, request GetImageByTokenRequestObject) (GetImageByTokenResponseObject, error)

	// (HEAD /api/v1/image/bytoken/{token}/{name})
	HeadImageByToken(ctx context.Context, request HeadImageByTokenRequestObject) (HeadImageByTokenResponseObject, error)

	// (GET /health)
	Health(ctx context.Context, request HealthRequestObject) (HealthResponseObject, error)
}

type StrictHandlerFunc = strictnethttp.StrictHTTPHandlerFunc
type StrictMiddlewareFunc = strictnethttp.StrictHTTPMiddlewareFunc

type StrictHTTPServerOptions struct {
	RequestErrorHandlerFunc  func(w http.ResponseWriter, r *http.Request, err error)
	ResponseErrorHandlerFunc func(w http.ResponseWriter, r *http.Request, err error)
}

func NewStrictHandler(ssi StrictServerInterface, middlewares []StrictMiddlewareFunc) ServerInterface {
	return &strictHandler{ssi: ssi, middlewares: middlewares, options: StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		},
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		},
	}}
}

func NewStrictHandlerWithOptions(ssi StrictServerInterface, middlewares []StrictMiddlewareFunc, options StrictHTTPServerOptions) ServerInterface {
	return &strictHandler{ssi: ssi, middlewares: middlewares, options: options}
}

type strictHandler struct {
	ssi         StrictServerInterface
	middlewares []StrictMiddlewareFunc
	options     StrictHTTPServerOptions
}

// GetImageByToken operation middleware
func (sh *strictHandler) GetImageByToken(w http.ResponseWriter, r *http.Request, token string, name string) {
	var request GetImageByTokenRequestObject

	request.Token = token
	request.Name = name

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.GetImageByToken(ctx, request.(GetImageByTokenRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "GetImageByToken")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(GetImageByTokenResponseObject); ok {
		if err := validResponse.VisitGetImageByTokenResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// HeadImageByToken operation middleware
func (sh *strictHandler) HeadImageByToken(w http.ResponseWriter, r *http.Request, token string, name string) {
	var request HeadImageByTokenRequestObject

	request.Token = token
	request.Name = name

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.HeadImageByToken(ctx, request.(HeadImageByTokenRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "HeadImageByToken")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(HeadImageByTokenResponseObject); ok {
		if err := validResponse.VisitHeadImageByTokenResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// Health operation middleware
func (sh *strictHandler) Health(w http.ResponseWriter, r *http.Request) {
	var request HealthRequestObject

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.Health(ctx, request.(HealthRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "Health")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(HealthResponseObject); ok {
		if err := validResponse.VisitHealthResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}
