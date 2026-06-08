package domain

import "time"

type Airport struct {
	AirportCode string
	AirportName string
	City        string
	Country     string
}

type City struct {
	Name string
}

type ScheduleItem struct {
	DaysOfWeek []int
	Time       string
	FlightNo   string
	Airport    string
}

type FlightSegment struct {
	FlightNo         string
	DepartureAirport string
	DepartureCity    string
	ArrivalAirport   string
	ArrivalCity      string
	DepartureTime    time.Time
	ArrivalTime      time.Time
	AircraftCode     string
	Price            float64
}

type RouteSearchResult struct {
	Segments    []FlightSegment
	Connections int
	TotalPrice  float64
}

type BookingInput struct {
	PassengerID   string
	PassengerName string
	BookingClass  string
	FlightIDs     []int64
}

type BookingResult struct {
	BookRef    string
	TicketNo   string
	TotalPrice float64
}

type CheckInInput struct {
	TicketNo string
	FlightID int64
	SeatNo   string
}

type CheckInResult struct {
	TicketNo     string
	FlightID     int64
	SeatNo       string
	BoardingNo   int
	BoardingTime time.Time
}
