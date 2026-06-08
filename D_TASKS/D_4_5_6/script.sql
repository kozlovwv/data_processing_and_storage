SELECT * FROM information_schema.tables
WHERE table_schema  = 'bookings';

SELECT * FROM airplanes a ;

SELECT * FROM airplanes_data ad ;

SELECT 
    t.route_no,
    t.departure_airport,
    t.arrival_airport,
    s.fare_conditions,
    MIN(s.price) AS min_price,
    ROUND(AVG(s.price), 2) as avg_round_price,
    MAX(s.price) AS max_price,
    COUNT(DISTINCT s.price) AS table_prices_count
FROM timetable t
JOIN segments s ON t.flight_id = s.flight_id
WHERE t.status IN ('Arrived', 'Departed')
GROUP BY t.route_no, t.departure_airport, t.arrival_airport, s.fare_conditions
ORDER BY t.route_no, s.fare_conditions;

CREATE OR REPLACE VIEW pricing_rules AS
SELECT 
    t.route_no,
    s.fare_conditions,
    MAX(s.price) AS established_price
FROM timetable t
JOIN segments s ON t.flight_id = s.flight_id
WHERE t.status IN ('Arrived', 'Departed')
GROUP BY t.route_no, s.fare_conditions;

select * from pricing_rules p ;

SELECT 
    t.flight_id,
    t.route_no,
    t.departure_airport,
    t.arrival_airport,
    t.scheduled_departure,
    st.seat_no,
    st.fare_conditions,
    COALESCE(pr.established_price, 0) AS calculated_price
FROM timetable t
JOIN seats st ON t.airplane_code = st.airplane_code
LEFT JOIN pricing_rules pr 
    ON t.route_no = pr.route_no 
   AND st.fare_conditions = pr.fare_conditions
WHERE t.status = 'Scheduled'
ORDER BY t.scheduled_departure, t.route_no, st.seat_no;