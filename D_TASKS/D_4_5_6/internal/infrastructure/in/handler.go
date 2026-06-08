package in

import (
	"airport/internal/application"
	"errors"

	"encoding/json"
	"net/http"
)

type AirportHandler struct {
	service *application.AirportService
}

func NewAirportHandler(service *application.AirportService) *AirportHandler {
	return &AirportHandler{
		service: service,
	}
}

func (h *AirportHandler) GetCities(w http.ResponseWriter, r *http.Request) {
	cities, err := h.service.GetCities(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	response := make([]string, 0, len(cities))
	for _, c := range cities {
		response = append(response, c.Name)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

func (h *AirportHandler) GetAirports(w http.ResponseWriter, r *http.Request) {
	cityParam := r.URL.Query().Get("city")

	airports, err := h.service.GetAirports(r.Context(), cityParam)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	response := make([]AirportResponse, 0, len(airports))
	for _, airport := range airports {
		response = append(response, MapAirportToResponse(airport))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

func (h *AirportHandler) GetInboundSchedule(w http.ResponseWriter, r *http.Request) {
	airportParam := r.URL.Query().Get("airport")

	schedule, err := h.service.GetInboundSchedule(r.Context(), airportParam)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	response := make([]InboundScheduleResponse, 0, len(schedule))
	for _, item := range schedule {
		response = append(response, MapToInboundResponse(item))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

func (h *AirportHandler) GetOutboundSchedule(w http.ResponseWriter, r *http.Request) {
	airportParam := r.URL.Query().Get("airport")

	schedule, err := h.service.GetOutboundSchedule(r.Context(), airportParam)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	response := make([]OutboundScheduleResponse, 0, len(schedule))
	for _, item := range schedule {
		response = append(response, MapToOutboundResponse(item))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

func (h *AirportHandler) GetSearchRoutes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")
	departureDate := r.URL.Query().Get("departure_date")
	bookingClass := r.URL.Query().Get("booking_class")
	maxConnections := r.URL.Query().Get("max_connections")

	routes, err := h.service.SearchRoutes(ctx, from, to, departureDate, bookingClass, maxConnections)
	if err != nil {
		if errors.Is(err, application.ErrInvalidBookingClass) ||
			errors.Is(err, application.ErrMissingDepartureDate) ||
			errors.Is(err, application.ErrInvalidConnections) {

			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(err.Error()))
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	response := make([]RouteSearchResponse, 0, len(routes))
	for _, r := range routes {
		response = append(response, MapToRouteSearchResponse(r))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

func (h *AirportHandler) CreateBooking(w http.ResponseWriter, r *http.Request) {
	var req BookingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid json body: " + err.Error()))
		return
	}

	if len(req.FlightIDs) == 0 {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("flight_ids array cannot be empty"))
		return
	}

	input := MapToBookingInput(req)

	result, err := h.service.CreateBooking(r.Context(), input)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	response := MapToBookingResponse(result)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

func (h *AirportHandler) CheckIn(w http.ResponseWriter, r *http.Request) {
	var req CheckInRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid json body"))
		return
	}

	if req.TicketNo == "" || req.FlightID == 0 || req.SeatNo == "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("ticket_no, flight_id and seat_no are required"))
		return
	}

	input := MapToCheckInInput(req)
	result, err := h.service.CheckIn(r.Context(), input)

	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		switch {
		case errors.Is(err, application.ErrTicketNotFound):
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(err.Error()))
		case errors.Is(err, application.ErrSeatAlreadyTaken), errors.Is(err, application.ErrSeatClassMismatch):
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(err.Error()))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	response := MapToCheckInResponse(result)
	_ = json.NewEncoder(w).Encode(response)
}
