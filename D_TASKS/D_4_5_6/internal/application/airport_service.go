package application

import (
	"airport/internal/domain"
	"airport/pkg/generator"
	"context"
	"errors"
	"strings"
	"time"
)

var (
	ErrInvalidBookingClass  = errors.New("invalid booking class: must be Economy, Comfort, or Business")
	ErrMissingDepartureDate = errors.New("departure date is mandatory and must be in YYYY-MM-DD format")
	ErrInvalidConnections   = errors.New("invalid max connections: must be 0, 1, 2, 3, or unbound")

	ErrTicketNotFound    = errors.New("ticket or flight segment not found")
	ErrSeatClassMismatch = errors.New("selected seat does not match the ticket fare conditions")
	ErrSeatAlreadyTaken  = errors.New("selected seat is already occupied on this flight")
)

type AirportRepository interface {
	GetAllCities(ctx context.Context) ([]domain.City, error)
	GetAllAirports(ctx context.Context) ([]domain.Airport, error)
	GetAirportsByCity(ctx context.Context, city string) ([]domain.Airport, error)

	GetInboundSchedule(ctx context.Context, airportCode string) ([]domain.ScheduleItem, error)
	GetOutboundSchedule(ctx context.Context, airportCode string) ([]domain.ScheduleItem, error)

	SearchRoutes(ctx context.Context, from, to string, departureDate time.Time, bookingClass string, maxConnections int) ([]domain.RouteSearchResult, error)

	CreateBooking(ctx context.Context, input domain.BookingInput, bookRef string, ticketNo string, bookDate time.Time) (domain.BookingResult, error)

	CreateBoardingPass(ctx context.Context, input domain.CheckInInput, boardingTime time.Time) (domain.CheckInResult, error)
}

type AirportService struct {
	repo AirportRepository
}

func NewAirportService(repo AirportRepository) *AirportService {
	return &AirportService{
		repo: repo,
	}
}

func (s *AirportService) GetCities(ctx context.Context) ([]domain.City, error) {
	return s.repo.GetAllCities(ctx)
}

func (s *AirportService) GetAirports(ctx context.Context, city string) ([]domain.Airport, error) {
	trimmedCity := strings.TrimSpace(city)

	if trimmedCity == "" {
		return s.repo.GetAllAirports(ctx)
	}
	return s.repo.GetAirportsByCity(ctx, trimmedCity)
}

func (s *AirportService) GetInboundSchedule(ctx context.Context, airportCode string) ([]domain.ScheduleItem, error) {
	code := strings.TrimSpace(airportCode)
	if code == "" {
		return []domain.ScheduleItem{}, nil
	}

	return s.repo.GetInboundSchedule(ctx, strings.ToUpper(code))
}

func (s *AirportService) GetOutboundSchedule(ctx context.Context, airportCode string) ([]domain.ScheduleItem, error) {
	code := strings.TrimSpace(airportCode)
	if code == "" {
		return []domain.ScheduleItem{}, nil
	}

	return s.repo.GetOutboundSchedule(ctx, strings.ToUpper(code))
}

func (s *AirportService) SearchRoutes(ctx context.Context, from, to, dateStr, bookingClass, connParam string) ([]domain.RouteSearchResult, error) {
	from = strings.TrimSpace(from)
	to = strings.TrimSpace(to)
	if from == "" || to == "" {
		return []domain.RouteSearchResult{}, nil
	}

	class := strings.Title(strings.ToLower(strings.TrimSpace(bookingClass)))
	if class != "Economy" && class != "Comfort" && class != "Business" {
		return nil, ErrInvalidBookingClass
	}

	parsedDate, err := time.Parse("2006-01-02", strings.TrimSpace(dateStr))
	if err != nil {
		return nil, ErrMissingDepartureDate
	}

	maxConn := -1
	connParam = strings.ToLower(strings.TrimSpace(connParam))
	if connParam != "" && connParam != "unbound" {
		switch connParam {
		case "0":
			maxConn = 0
		case "1":
			maxConn = 1
		case "2":
			maxConn = 2
		case "3":
			maxConn = 3
		default:
			return nil, ErrInvalidConnections
		}
	}

	return s.repo.SearchRoutes(ctx, from, to, parsedDate, class, maxConn)
}

func (s *AirportService) CreateBooking(ctx context.Context, input domain.BookingInput) (domain.BookingResult, error) {
	bookDate := time.Now()

	bookRef := generator.GenerateBookRef()
	ticketNo := generator.GenerateTicketNo()

	result, err := s.repo.CreateBooking(ctx, input, bookRef, ticketNo, bookDate)
	if err != nil {
		return domain.BookingResult{}, err
	}

	return result, nil
}

func (s *AirportService) CheckIn(ctx context.Context, input domain.CheckInInput) (domain.CheckInResult, error) {
	boardingTime := time.Now()

	result, err := s.repo.CreateBoardingPass(ctx, input, boardingTime)
	if err != nil {
		return domain.CheckInResult{}, err
	}

	return result, nil
}
