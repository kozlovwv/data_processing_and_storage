package out

import (
	"airport/internal/application"
	"airport/internal/domain"
	"errors"
	"fmt"
	"time"

	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{
		pool: pool,
	}
}

func (r *PostgresRepository) GetAllCities(ctx context.Context) ([]domain.City, error) {
	query := `
		SELECT DISTINCT city
		FROM airports
		ORDER BY city;
	`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cities []domain.City
	for rows.Next() {
		var city domain.City
		if err := rows.Scan(&city.Name); err != nil {
			return nil, err
		}
		cities = append(cities, city)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return cities, nil
}

func (r *PostgresRepository) GetAllAirports(ctx context.Context) ([]domain.Airport, error) {
	query := `
		SELECT 
			airport_code,
			airport_name,
			city,
			country
		FROM airports
		ORDER BY airport_code;
	`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var airports []domain.Airport
	for rows.Next() {
		var a domain.Airport
		err := rows.Scan(&a.AirportCode, &a.AirportName, &a.City, &a.Country)
		if err != nil {
			return nil, err
		}
		airports = append(airports, a)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return airports, nil
}

func (r *PostgresRepository) GetAirportsByCity(ctx context.Context, city string) ([]domain.Airport, error) {
	query := `
		SELECT 
			airport_code,
			airport_name,
			city,
			country
		FROM airports
		WHERE city = $1
		ORDER BY airport_code;
	`

	rows, err := r.pool.Query(ctx, query, city)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var airports []domain.Airport
	for rows.Next() {
		var a domain.Airport
		err := rows.Scan(&a.AirportCode, &a.AirportName, &a.City, &a.Country)
		if err != nil {
			return nil, err
		}
		airports = append(airports, a)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return airports, nil
}

func (r *PostgresRepository) GetInboundSchedule(ctx context.Context, airportCode string) ([]domain.ScheduleItem, error) {
	query := `
		SELECT 
			r.days_of_week,
			r.scheduled_time::TEXT,
			r.route_no,
			r.departure_airport as airport
		FROM routes r
		WHERE r.arrival_airport = $1
		AND r.validity @> bookings.now()
		ORDER BY r.scheduled_time
	`

	rows, err := r.pool.Query(ctx, query, airportCode)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var schedules []domain.ScheduleItem
	for rows.Next() {
		var s domain.ScheduleItem

		err := rows.Scan(
			&s.DaysOfWeek,
			&s.Time,
			&s.FlightNo,
			&s.Airport,
		)
		if err != nil {
			return nil, err
		}

		schedules = append(schedules, s)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return schedules, nil
}

func (r *PostgresRepository) GetOutboundSchedule(ctx context.Context, airportCode string) ([]domain.ScheduleItem, error) {
	query := `
		SELECT 
			r.days_of_week,
			r.scheduled_time::TEXT,
			r.route_no,
			r.arrival_airport as airport
		FROM routes r
		WHERE r.departure_airport = $1
		AND r.validity @> bookings.now()
		ORDER BY r.scheduled_time
	`

	rows, err := r.pool.Query(ctx, query, airportCode)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var schedules []domain.ScheduleItem
	for rows.Next() {
		var s domain.ScheduleItem

		err := rows.Scan(
			&s.DaysOfWeek,
			&s.Time,
			&s.FlightNo,
			&s.Airport,
		)
		if err != nil {
			return nil, err
		}

		schedules = append(schedules, s)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return schedules, nil
}

func (r *PostgresRepository) SearchRoutes(
	ctx context.Context,
	from, to string,
	departureDate time.Time,
	bookingClass string,
	maxConnections int,
) ([]domain.RouteSearchResult, error) {

	dateStart := departureDate.Format("2006-01-02") + " 00:00:00"
	dateEnd := departureDate.Format("2006-01-02") + " 23:59:59"

	query := `
		WITH RECURSIVE flight_paths AS (
			SELECT
				f.flight_id,
				r.route_no,
				r.departure_airport,
				dep.city AS departure_city,
				r.arrival_airport,
				arr.city AS arrival_city,
				f.scheduled_departure,
				f.scheduled_arrival,
				r.airplane_code,
				0 AS connections,
				ARRAY[f.flight_id] AS path_ids,
				ARRAY[r.departure_airport, r.arrival_airport]::text[] AS path_airports
			FROM flights f
			JOIN routes r ON f.route_no = r.route_no
			JOIN airports dep ON r.departure_airport = dep.airport_code
			JOIN airports arr ON r.arrival_airport = arr.airport_code
			WHERE (r.departure_airport = $1 OR dep.city = $1)
				AND f.scheduled_departure BETWEEN $3::TIMESTAMP AND $4::TIMESTAMP
				AND r.airplane_code IN (
					SELECT DISTINCT airplane_code FROM seats WHERE fare_conditions = $5
				)

			UNION ALL

			SELECT
				f_next.flight_id,
				r_next.route_no,
				p.departure_airport,
				p.departure_city,
				r_next.arrival_airport,
				arr_next.city AS arrival_city,
				p.scheduled_departure,
				f_next.scheduled_arrival,
				r_next.airplane_code,
				p.connections + 1 AS connections,
				p.path_ids || f_next.flight_id,
				p.path_airports || r_next.arrival_airport
			FROM flights f_next
			JOIN routes r_next ON f_next.route_no = r_next.route_no
			JOIN airports arr_next ON r_next.arrival_airport = arr_next.airport_code
			JOIN flight_paths p ON r_next.departure_airport = p.arrival_airport
			WHERE ((p.connections + 1) <= $6 OR $6 = -1)
				AND f_next.scheduled_departure BETWEEN p.scheduled_arrival + INTERVAL '1 hour' AND p.scheduled_arrival + INTERVAL '24 hours'
				AND NOT (r_next.arrival_airport = ANY(p.path_airports))
				AND r_next.airplane_code IN (
					SELECT DISTINCT airplane_code FROM seats WHERE fare_conditions = $5
				)
		)
		SELECT
			fp.path_ids,
			fp.connections
		FROM flight_paths fp
		JOIN airports dst ON fp.arrival_airport = dst.airport_code
		WHERE (fp.arrival_airport = $2 OR dst.city = $2)
		GROUP BY fp.path_ids, fp.connections
		ORDER BY fp.connections;
	`

	// Параметры: $1=from, $2=to, $3=dateStart, $4=dateEnd, $5=bookingClass, $6=maxConnections
	rows, err := r.pool.Query(ctx, query, from, to, dateStart, dateEnd, bookingClass, maxConnections)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type rawPath struct {
		pathIDs     []int64
		connections int
	}

	var rawPaths []rawPath
	for rows.Next() {
		var rp rawPath
		if err := rows.Scan(&rp.pathIDs, &rp.connections); err != nil {
			return nil, err
		}
		rawPaths = append(rawPaths, rp)
	}

	if len(rawPaths) == 0 {
		return []domain.RouteSearchResult{}, nil
	}

	var results []domain.RouteSearchResult
	for _, p := range rawPaths {
		segments, err := r.fetchSegmentsData(ctx, p.pathIDs, bookingClass)
		if err != nil {
			return nil, err
		}

		var totalPrice float64
		for _, seg := range segments {
			totalPrice += seg.Price
		}

		results = append(results, domain.RouteSearchResult{
			Segments:    segments,
			Connections: p.connections,
			TotalPrice:  totalPrice,
		})
	}

	return results, nil
}

func (r *PostgresRepository) fetchSegmentsData(ctx context.Context, pathIDs []int64, fareConditions string) ([]domain.FlightSegment, error) {
	query := `
		SELECT DISTINCT ON (array_position($1, f.flight_id), f.flight_id)
			r.route_no,
			r.departure_airport,
			dep.city AS departure_city,
			r.arrival_airport,
			arr.city AS arrival_city,
			f.scheduled_departure,
			f.scheduled_arrival,
			r.airplane_code,
			COALESCE(pr.established_price, 0.00) AS segment_price
		FROM flights f
		JOIN routes r ON f.route_no = r.route_no
		JOIN airports dep ON r.departure_airport = dep.airport_code
		JOIN airports arr ON r.arrival_airport = arr.airport_code
		LEFT JOIN pricing_rules pr ON r.route_no = pr.route_no AND pr.fare_conditions = $2
		WHERE f.flight_id = ANY($1)
		ORDER BY array_position($1, f.flight_id), f.flight_id;
	`

	rows, err := r.pool.Query(ctx, query, pathIDs, fareConditions)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var segments []domain.FlightSegment
	for rows.Next() {
		var seg domain.FlightSegment
		err := rows.Scan(
			&seg.FlightNo,
			&seg.DepartureAirport,
			&seg.DepartureCity,
			&seg.ArrivalAirport,
			&seg.ArrivalCity,
			&seg.DepartureTime,
			&seg.ArrivalTime,
			&seg.AircraftCode,
			&seg.Price,
		)
		if err != nil {
			return nil, err
		}
		segments = append(segments, seg)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return segments, nil
}

func (r *PostgresRepository) CreateBooking(ctx context.Context, input domain.BookingInput, bookRef string, ticketNo string, bookDate time.Time) (domain.BookingResult, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.BookingResult{}, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, "SELECT 1 FROM flights WHERE flight_id = ANY($1) FOR UPDATE;", input.FlightIDs)
	if err != nil {
		return domain.BookingResult{}, fmt.Errorf("failed to lock flights rows: %w", err)
	}

	// fmt.Printf("1. Attempting to create booking for passenger %s with flights %v\n", input.PassengerName, input.FlightIDs)

	checkAndPriceQuery := `
		SELECT 
			f.flight_id, 
			COALESCE(pr.established_price, 0.00) AS price,
			(SELECT COUNT(*) FROM seats s WHERE s.airplane_code = r.airplane_code AND s.fare_conditions = $2) AS total_seats,
			(SELECT COUNT(*) FROM segments seg WHERE seg.flight_id = f.flight_id AND seg.fare_conditions = $2) AS occupied_seats
		FROM flights f
		JOIN routes r ON f.route_no = r.route_no
		LEFT JOIN pricing_rules pr ON r.route_no = pr.route_no AND pr.fare_conditions = $2
		WHERE f.flight_id = ANY($1);
	`
	rows, err := tx.Query(ctx, checkAndPriceQuery, input.FlightIDs, input.BookingClass)
	if err != nil {
		return domain.BookingResult{}, fmt.Errorf("failed to fetch prices for segments: %w", err)
	}
	defer rows.Close()

	// fmt.Printf("2. Attempting to create booking for passenger %s with flights %v\n", input.PassengerName, input.FlightIDs)

	flightPrices := make(map[int64]float64)
	var totalPrice float64

	for rows.Next() {
		var fid int64
		var price float64
		var totalSeats, occupiedSeats int64

		if err := rows.Scan(&fid, &price, &totalSeats, &occupiedSeats); err != nil {
			return domain.BookingResult{}, fmt.Errorf("failed to scan row: %w", err)
		}

		if occupiedSeats >= totalSeats {
			// fmt.Printf("3. No seats available for flight %d in class %s (occupied: %d, total: %d)\n", fid, input.BookingClass, occupiedSeats, totalSeats)
			return domain.BookingResult{}, fmt.Errorf("no seats available on flight %d for class %s (seats: %d/%d)", fid, input.BookingClass, occupiedSeats, totalSeats)
		}

		flightPrices[fid] = price
		totalPrice += price
	}

	// fmt.Printf("Calculated total price: %.2f for booking with flights %v\n", totalPrice, input.FlightIDs)

	if err := rows.Err(); err != nil {
		return domain.BookingResult{}, err
	}

	if len(flightPrices) != len(input.FlightIDs) {
		return domain.BookingResult{}, fmt.Errorf("some flight IDs were not found in the database")
	}

	insertBookingQuery := `
		INSERT INTO bookings (book_ref, book_date, total_amount)
		VALUES ($1, $2, $3);
	`
	_, err = tx.Exec(ctx, insertBookingQuery, bookRef, bookDate, totalPrice)
	if err != nil {
		return domain.BookingResult{}, fmt.Errorf("failed to insert into bookings: %w", err)
	}

	insertTicketQuery := `
		INSERT INTO tickets (ticket_no, book_ref, passenger_id, passenger_name, outbound)
		VALUES ($1, $2, $3, $4, $5);
	`
	_, err = tx.Exec(ctx, insertTicketQuery, ticketNo, bookRef, input.PassengerID, input.PassengerName, true)
	if err != nil {
		return domain.BookingResult{}, fmt.Errorf("failed to insert into tickets: %w", err)
	}

	insertSegmentQuery := `
		INSERT INTO segments (ticket_no, flight_id, fare_conditions, price)
		VALUES ($1, $2, $3, $4);
	`
	for i, flightID := range input.FlightIDs {
		price := flightPrices[flightID]
		_, err = tx.Exec(ctx, insertSegmentQuery, ticketNo, flightID, input.BookingClass, price)
		if err != nil {
			return domain.BookingResult{}, fmt.Errorf("failed to insert segment %d into segments table: %w", i, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.BookingResult{}, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return domain.BookingResult{
		BookRef:    bookRef,
		TicketNo:   ticketNo,
		TotalPrice: totalPrice,
	}, nil
}

func (r *PostgresRepository) CreateBoardingPass(ctx context.Context, input domain.CheckInInput, boardingTime time.Time) (domain.CheckInResult, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.CheckInResult{}, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	validationQuery := `
		SELECT 
			seg.fare_conditions AS ticket_fare,
			s.fare_conditions AS seat_fare,
			(SELECT COUNT(*) FROM boarding_passes bp WHERE bp.flight_id = seg.flight_id AND bp.seat_no = $3) AS is_occupied
		FROM segments seg
		JOIN flights f ON seg.flight_id = f.flight_id
		JOIN routes r ON f.route_no = r.route_no
		LEFT JOIN seats s ON s.airplane_code = r.airplane_code AND s.seat_no = $3
		WHERE seg.ticket_no = $1 AND seg.flight_id = $2
		FOR UPDATE OF seg;
	`

	var ticketFare string
	var seatFare *string
	var isOccupied int

	err = tx.QueryRow(ctx, validationQuery, input.TicketNo, input.FlightID, input.SeatNo).Scan(&ticketFare, &seatFare, &isOccupied)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			
			// fmt.Printf("1 Check-in failed: ticket %s for flight %d not found or seat %s does not exist\n", input.TicketNo, input.FlightID, input.SeatNo)

			return domain.CheckInResult{}, application.ErrTicketNotFound
		}

		// fmt.Printf("2 Check-in failed for ticket %s on flight %d, seat %s: %v\n", input.TicketNo, input.FlightID, input.SeatNo, err)

		return domain.CheckInResult{}, fmt.Errorf("failed to validate ticket and seat: %w", err)
	}

	// fmt.Printf("3 Check-in validation passed for ticket %s on flight %d, seat %s\n", input.TicketNo, input.FlightID, input.SeatNo)

	if seatFare == nil {
		return domain.CheckInResult{}, fmt.Errorf("%w: seat %s does not exist on this aircraft", application.ErrSeatClassMismatch, input.SeatNo)
	}

	// fmt.Printf("4 Check-in validation passed for ticket %s on flight %d, seat %s\n", input.TicketNo, input.FlightID, input.SeatNo)

	if ticketFare != *seatFare {
		return domain.CheckInResult{}, fmt.Errorf("%w: ticket is %s, but seat %s is %s", application.ErrSeatClassMismatch, ticketFare, input.SeatNo, *seatFare)
	}

	// fmt.Printf("5 Check-in validation passed for ticket %s on flight %d, seat %s\n", input.TicketNo, input.FlightID, input.SeatNo)

	if isOccupied > 0 {
		return domain.CheckInResult{}, fmt.Errorf("%w: seat %s is already taken", application.ErrSeatAlreadyTaken, input.SeatNo)
	}

	// fmt.Printf("6 Check-in validation passed for ticket %s on flight %d, seat %s\n", input.TicketNo, input.FlightID, input.SeatNo)

	boardingNoQuery := `
		SELECT COALESCE(MAX(boarding_no), 0) + 1 
		FROM boarding_passes 
		WHERE flight_id = $1;
	`
	var nextBoardingNo int
	err = tx.QueryRow(ctx, boardingNoQuery, input.FlightID).Scan(&nextBoardingNo)
	if err != nil {
		return domain.CheckInResult{}, fmt.Errorf("failed to calculate next boarding number: %w", err)
	}

	insertPassQuery := `
		INSERT INTO boarding_passes (ticket_no, flight_id, seat_no, boarding_no, boarding_time)
		VALUES ($1, $2, $3, $4, $5);
	`
	_, err = tx.Exec(ctx, insertPassQuery, input.TicketNo, input.FlightID, input.SeatNo, nextBoardingNo, boardingTime)
	if err != nil {
		return domain.CheckInResult{}, fmt.Errorf("failed to insert boarding pass: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.CheckInResult{}, fmt.Errorf("failed to commit check-in transaction: %w", err)
	}

	return domain.CheckInResult{
		TicketNo:     input.TicketNo,
		FlightID:     input.FlightID,
		SeatNo:       input.SeatNo,
		BoardingNo:   nextBoardingNo,
		BoardingTime: boardingTime,
	}, nil
}
