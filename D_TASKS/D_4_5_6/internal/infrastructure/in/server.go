package in

import (
	"context"
	"net/http"
	"time"
)

type Server struct {
	httpServer *http.Server
}

func NewServer(addr string, airportHandler *AirportHandler) *Server {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /cities", airportHandler.GetCities)
	mux.HandleFunc("GET /airports", airportHandler.GetAirports)
	mux.HandleFunc("GET /inbound", airportHandler.GetInboundSchedule)
	mux.HandleFunc("GET /outbound", airportHandler.GetOutboundSchedule)
	mux.HandleFunc("GET /routes", airportHandler.GetSearchRoutes)
	mux.HandleFunc("POST /bookings", airportHandler.CreateBooking)
	mux.HandleFunc("POST /check-in", airportHandler.CheckIn)

	return &Server{
		httpServer: &http.Server{
			Addr:         addr,
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		},
	}
}

func (s *Server) Start() error {
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}