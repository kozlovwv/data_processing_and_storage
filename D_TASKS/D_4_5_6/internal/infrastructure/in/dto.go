package in

import (
	"airport/internal/domain"
	"time"
)

type CityResponse struct {
	City string `json:"city"`
}

type AirportResponse struct {
	AirportCode string `json:"airport_code"`
	AirportName string `json:"airport_name"`
	City        string `json:"city"`
	Country     string `json:"country"`
}

type InboundScheduleResponse struct {
	DaysOfWeek    []int  `json:"days_of_week"`
	TimeOfArrival string `json:"time_of_arrival"`
	FlightNo      string `json:"flight_no"`
	Origin        string `json:"origin"`
}

type OutboundScheduleResponse struct {
	DaysOfWeek      []int  `json:"days_of_week"`
	TimeOfDeparture string `json:"time_of_departure"`
	FlightNo        string `json:"flight_no"`
	Destination     string `json:"destination"`
}

type FlightSegmentDTO struct {
	FlightNo         string    `json:"flight_no"`
	DepartureAirport string    `json:"departure_airport"`
	DepartureCity    string    `json:"departure_city"`
	ArrivalAirport   string    `json:"arrival_airport"`
	ArrivalCity      string    `json:"arrival_city"`
	DepartureTime    time.Time `json:"departure_time"`
	ArrivalTime      time.Time `json:"arrival_time"`
	AircraftCode     string    `json:"aircraft_code"`
	Price            float64   `json:"price"`
}

type RouteSearchResponse struct {
	TotalPrice  float64            `json:"total_price"`
	Connections int                `json:"connections"`
	Segments    []FlightSegmentDTO `json:"segments"`
}

type BookingRequest struct {
	PassengerID   string  `json:"passenger_id" binding:"required"`
	PassengerName string  `json:"passenger_name" binding:"required"`
	BookingClass  string  `json:"booking_class" binding:"required"`
	FlightIDs     []int64 `json:"flight_ids" binding:"required,min=1"`
}

type BookingResponse struct {
	BookRef    string  `json:"book_ref"`
	TicketNo   string  `json:"ticket_no"`
	TotalPrice float64 `json:"total_price"`
}

type CheckInRequest struct {
	TicketNo string `json:"ticket_no"`
	FlightID int64  `json:"flight_id"`
	SeatNo   string `json:"seat_no"`
}

type CheckInResponse struct {
	TicketNo     string    `json:"ticket_no"`
	FlightID     int64     `json:"flight_id"`
	SeatNo       string    `json:"seat_no"`
	BoardingNo   int       `json:"boarding_no"`
	BoardingTime time.Time `json:"boarding_time"`
}

func MapCityToResponse(c domain.City) CityResponse {
	return CityResponse{
		City: c.Name,
	}
}

func MapAirportToResponse(a domain.Airport) AirportResponse {
	return AirportResponse{
		AirportCode: a.AirportCode,
		AirportName: a.AirportName,
		City:        a.City,
		Country:     a.Country,
	}
}

func MapToInboundResponse(item domain.ScheduleItem) InboundScheduleResponse {
	return InboundScheduleResponse{
		DaysOfWeek:    item.DaysOfWeek,
		TimeOfArrival: item.Time,
		FlightNo:      item.FlightNo,
		Origin:        item.Airport,
	}
}

func MapToOutboundResponse(item domain.ScheduleItem) OutboundScheduleResponse {
	return OutboundScheduleResponse{
		DaysOfWeek:      item.DaysOfWeek,
		TimeOfDeparture: item.Time,
		FlightNo:        item.FlightNo,
		Destination:     item.Airport,
	}
}

func MapToRouteSearchResponse(res domain.RouteSearchResult) RouteSearchResponse {
	segmentsDTO := make([]FlightSegmentDTO, 0, len(res.Segments))

	for _, seg := range res.Segments {
		segmentsDTO = append(segmentsDTO, FlightSegmentDTO{
			FlightNo:         seg.FlightNo,
			DepartureAirport: seg.DepartureAirport,
			DepartureCity:    seg.DepartureCity,
			ArrivalAirport:   seg.ArrivalAirport,
			ArrivalCity:      seg.ArrivalCity,
			DepartureTime:    seg.DepartureTime,
			ArrivalTime:      seg.ArrivalTime,
			AircraftCode:     seg.AircraftCode,
			Price:            seg.Price,
		})
	}

	return RouteSearchResponse{
		TotalPrice:  res.TotalPrice,
		Connections: res.Connections,
		Segments:    segmentsDTO,
	}
}

func MapToBookingInput(req BookingRequest) domain.BookingInput {
	return domain.BookingInput{
		PassengerID:   req.PassengerID,
		PassengerName: req.PassengerName,
		BookingClass:  req.BookingClass,
		FlightIDs:     req.FlightIDs,
	}
}

func MapToBookingResponse(res domain.BookingResult) BookingResponse {
	return BookingResponse{
		BookRef:    res.BookRef,
		TicketNo:   res.TicketNo,
		TotalPrice: res.TotalPrice,
	}
}

func MapToCheckInInput(req CheckInRequest) domain.CheckInInput {
	return domain.CheckInInput{
		TicketNo: req.TicketNo,
		FlightID: req.FlightID,
		SeatNo:   req.SeatNo,
	}
}

func MapToCheckInResponse(res domain.CheckInResult) CheckInResponse {
	return CheckInResponse{
		TicketNo:     res.TicketNo,
		FlightID:     res.FlightID,
		SeatNo:       res.SeatNo,
		BoardingNo:   res.BoardingNo,
		BoardingTime: res.BoardingTime,
	}
}