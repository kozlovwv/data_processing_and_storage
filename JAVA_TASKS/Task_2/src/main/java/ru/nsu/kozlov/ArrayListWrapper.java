package ru.nsu.kozlov;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

public class ArrayListWrapper {
    private static final AtomicInteger totalSwaps = new AtomicInteger(0);

    public static void main(String[] args) throws InterruptedException {
        List<String> list = Collections.synchronizedList(new ArrayList<>());
        Scanner scanner = new Scanner(System.in);
        System.out.print("Введите количество потоков: ");
        int threadCount = Integer.parseInt(scanner.nextLine());
        if (threadCount <= 0) {
            System.out.println("Количество потоков должно быть больше 0!");
            scanner.close();
            return;
        }
        System.out.print("Введите время задержки: ");
        int delay = Integer.parseInt(scanner.nextLine());
        if (delay < 0) {
            System.out.println("Задержка не может быть отрицательной!");
            scanner.close();
            return;
        }

        List<ArrayListSorter> sorters = new ArrayList<>();
        Thread[] threads = new Thread[threadCount];

        System.out.println("Запускаем " + threadCount + " потоков с задержкой " + delay + "мс");
        for (int i = 0; i < threadCount; i++) {
            ArrayListSorter sorter = new ArrayListSorter(list, "Sorter-" + (i + 1), delay, totalSwaps);
            sorters.add(sorter);
            threads[i] = new Thread(sorter);
            threads[i].start();
        }

        while (true) {
            String input = scanner.nextLine();
            if (input.equals("STOP")) {
                System.out.println("Получена команда STOP. Останавливаем потоки...");
                break;
            }
            else if (input.isEmpty()) {
                System.out.println("Текущее состояние списка: " + list);
                System.out.println("Всего перестановок: " + totalSwaps.get());
            }
            else {
                if (input.length() > 80) {
                    for (int i = 0; i < input.length(); i += 80) {
                        int endIndex = Math.min(i + 80, input.length());
                        String part = input.substring(i, endIndex);
                        list.addFirst(part);
                        System.out.println("Добавлена часть строки: " + part);
                    }
                } else {
                    list.addFirst(input);
                    System.out.println("Добавлена строка: " + input);
                }
            }
        }

        for (ArrayListSorter sorter : sorters) {
            sorter.stopSorting();
        }

        for (int i = 0; i < threadCount; i++) {
            threads[i].join();
        }

        System.out.println("Финальный список: " + list);
        scanner.close();
    }
}

class ArrayListSorter implements Runnable {
    private final List<String> list;
    private final String name;
    private final int delay;
    private final AtomicInteger totalSwaps;
    private boolean running = true;
    private int swapCount = 0;
    private int iterations = 0;

    public ArrayListSorter(List<String> list, String name, int delay, AtomicInteger totalSwaps) {
        this.list = list;
        this.name = name;
        this.delay = delay;
        this.totalSwaps = totalSwaps;
    }

    @Override
    public void run() {
        System.out.println(name + " начал работу");

        while (running && !Thread.currentThread().isInterrupted()) {
            boolean swapped = performBubbleSortIteration();
            iterations++;
            if (swapped) {
                System.out.println(name + " сделал перестановку в итерации " + iterations);
            }
            try {
                Thread.sleep(delay);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        System.out.println(name + " завершил работу. Итераций: " + iterations + ", перестановок: " + swapCount);
    }

    private boolean performBubbleSortIteration() {
        boolean swapped = false;
        synchronized(list) {
            for (int i = 0; i < list.size() - 1 && running; i++) {
                try {
                    if (delay > 0) {
                        Thread.sleep(delay / Math.max(1, list.size()));
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
                String current = list.get(i);
                String next = list.get(i + 1);
                if (current.compareTo(next) > 0) {
                    list.set(i, next);
                    list.set(i + 1, current);
                    swapped = true;
                    swapCount++;
                    totalSwaps.incrementAndGet();
                    System.out.println(name + " поменял '" + current + "' и '" + next + "'");
                }
            }
        }
        return swapped;
    }

    public void stopSorting() {
        running = false;
    }

    public int getSwapCount() {
        return swapCount;
    }

    public String getName() {
        return name;
    }
}
