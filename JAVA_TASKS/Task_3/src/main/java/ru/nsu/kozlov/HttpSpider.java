package ru.nsu.kozlov;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class HttpSpider {
    private final String baseUrl;
    private final HttpClient httpClient;
    private final ExecutorService virtualThreadExecutor;
    private final Semaphore requestSemaphore;
    private final ConcurrentSkipListSet<String> messages;
    private final Set<String> visitedPaths;
    private final ObjectMapper objectMapper;
    private final Phaser phaser;
    private final AtomicInteger totalRequests;
    private final AtomicInteger successfulRequests;
    private final AtomicInteger failedRequests;
    private final long startTime;

    public HttpSpider(String host, int port, int maxConcurrentRequests) {
        this.baseUrl = "http://" + host + ":" + port;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .build();
        this.virtualThreadExecutor = Executors.newVirtualThreadPerTaskExecutor();
        this.requestSemaphore = new Semaphore(maxConcurrentRequests);
        this.messages = new ConcurrentSkipListSet<>();
        this.visitedPaths = ConcurrentHashMap.newKeySet();
        this.objectMapper = new ObjectMapper();
        this.phaser = new Phaser(1);
        this.totalRequests = new AtomicInteger(0);
        this.successfulRequests = new AtomicInteger(0);
        this.failedRequests = new AtomicInteger(0);
        this.startTime = System.currentTimeMillis();
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: java HttpSpider <host> <port> <maxConcurrentRequests>");
            System.err.println("Example: java HttpSpider localhost 8080 10");
            return;
        }

        String host = args[0];
        int port = args.length > 1 ? Integer.parseInt(args[1]) : 8080;
        int maxConcurrentRequests = args.length > 2 ? Integer.parseInt(args[2]) : 10;

        System.out.println("Starting HTTP Spider at " + getCurrentTime());
        System.out.println("Target: " + host + ":" + port);
        System.out.println("Max concurrent requests: " + maxConcurrentRequests);
        System.out.println("Timeout: 120 seconds");
        System.out.println("=" .repeat(50));

        HttpSpider spider = new HttpSpider(host, port, maxConcurrentRequests);

        try {
            List<String> result = spider.crawl();
            System.out.println("\n" + "=" .repeat(50));
            System.out.println("CRAWLING COMPLETED!");
            System.out.println("Results:");
            System.out.println("  Total messages: " + result.size());
            System.out.println("  Total requests: " + spider.totalRequests.get());
            System.out.println("  Successful: " + spider.successfulRequests.get());
            System.out.println("  Failed: " + spider.failedRequests.get());
            System.out.println("  Total time: " + spider.getElapsedTime() + " seconds");
            System.out.println("\n=== Collected Messages ===");
            result.forEach(System.out::println);
        } finally {
            spider.shutdown();
        }
    }

    public List<String> crawl() throws InterruptedException {
        crawlPath("/");

        // Периодически выводим статус во время ожидания
        Thread statusThread = new Thread(() -> {
            while (!phaser.isTerminated()) {
                try {
                    Thread.sleep(10000); // Каждые 10 секунд
                    printStatus();
                } catch (InterruptedException e) {
                    break;
                }
            }
        });
        statusThread.setDaemon(true);
        statusThread.start();

        System.out.println("Waiting for all tasks to complete...");
        phaser.arriveAndAwaitAdvance();

        virtualThreadExecutor.shutdown();
        if (!virtualThreadExecutor.awaitTermination(10, TimeUnit.SECONDS)) {
            System.out.println("Forcing shutdown...");
            virtualThreadExecutor.shutdownNow();
        }

        return new ArrayList<>(messages);
    }

    private void crawlPath(String path) {
        if (!visitedPaths.add(path)) {
            return;
        }

        phaser.register();

        virtualThreadExecutor.submit(() -> {
            try {
                requestSemaphore.acquire();
                try {
                    totalRequests.incrementAndGet();
                    ResponseData response = fetchPath(path);
                    if (response != null) {
                        successfulRequests.incrementAndGet();
                        messages.add(response.message());

                        if (successfulRequests.get() % 50 == 0) {
                            System.out.println(getCurrentTime() + " Progress: " +
                                    successfulRequests.get() + " successful, " +
                                    visitedPaths.size() + " paths visited, " +
                                    getElapsedTime() + "s elapsed");
                        }

                        // Обрабатываем successors
                        for (String successor : response.successors()) {
                            String successorPath = normalizePath(successor);
                            crawlPath(successorPath);
                        }
                    } else {
                        failedRequests.incrementAndGet();
                    }
                } finally {
                    requestSemaphore.release();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                failedRequests.incrementAndGet();
                System.err.println(getCurrentTime() + " Error crawling " + path + ": " + e.getMessage());
            } finally {
                phaser.arriveAndDeregister();
            }
        });
    }

    private String normalizePath(String path) {
        if (path == null || path.isEmpty()) {
            return "/";
        }
        return path.startsWith("/") ? path : "/" + path;
    }

    private ResponseData fetchPath(String path) {
        try {
            String normalizedPath = normalizePath(path);
            String fullUrl = baseUrl + normalizedPath;

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(fullUrl))
                    .timeout(Duration.ofSeconds(15))
                    .GET()
                    .build();

            long requestStart = System.currentTimeMillis();
            HttpResponse<String> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofString());
            long requestTime = System.currentTimeMillis() - requestStart;

            if (response.statusCode() == 200) {
                ResponseData data = objectMapper.readValue(response.body(), ResponseData.class);

                // Выводим информацию о медленных запросах
                if (requestTime > 5000) {
                    System.out.println(getCurrentTime() + " Slow request: " + path +
                            " took " + requestTime + "ms, " +
                            data.successors().size() + " successors");
                } else if (successfulRequests.get() % 20 == 0) {
                    System.out.println(getCurrentTime() + " Fetched: " + path +
                            " (msg: " + data.message() + ", " +
                            data.successors().size() + " successors)");
                }

                return data;
            } else {
                System.err.println(getCurrentTime() + " HTTP " + response.statusCode() + " for: " + path);
                return null;
            }
        } catch (Exception e) {
            System.err.println(getCurrentTime() + " Failed to fetch " + path + ": " + e.getMessage());
            return null;
        }
    }

    private void printStatus() {
        long elapsed = getElapsedTime();
        int total = totalRequests.get();
        int success = successfulRequests.get();
        int fail = failedRequests.get();
        int visited = visitedPaths.size();
        int messagesCount = messages.size();
        int active = phaser.getRegisteredParties() - phaser.getArrivedParties();

        System.out.println("\nSTATUS UPDATE at " + getCurrentTime());
        System.out.println("  Elapsed time: " + elapsed + "s");
        System.out.println("  Requests: " + total + " (success: " + success + " | failed: " + fail + ")");
        System.out.println("  Visited paths: " + visited);
        System.out.println("  Messages collected: " + messagesCount);
        System.out.println("  Active tasks: " + active);
        System.out.println("  Available permits: " + requestSemaphore.availablePermits());
        System.out.println("  Progress: " + String.format("%.1f", (success * 100.0 / 1000)) + "%");
        System.out.println("  Time remaining: " + Math.max(0, 120 - elapsed) + "s");
        System.out.println("-".repeat(50));
    }

    private long getElapsedTime() {
        return (System.currentTimeMillis() - startTime) / 1000;
    }

    private static String getCurrentTime() {
        return LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
    }

    public void shutdown() {
        virtualThreadExecutor.shutdown();
    }

    public record ResponseData(
            @JsonProperty("message") String message,
            @JsonProperty("successors") List<String> successors
    ) {}
}