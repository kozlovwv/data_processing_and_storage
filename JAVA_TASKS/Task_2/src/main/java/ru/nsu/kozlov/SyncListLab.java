package ru.nsu.kozlov;

import java.util.*;
import java.util.concurrent.locks.ReentrantLock;

public class SyncListLab {
    public static void main(String[] args) throws InterruptedException {
        MySyncList list = new MySyncList();
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

        List<ListSorter> sorters = new ArrayList<>();
        Thread[] threads = new Thread[threadCount];

        for (int i = 0; i < threadCount; i++) {
            ListSorter sorter = new ListSorter(list, delay);
            sorters.add(sorter);
            threads[i] = new Thread(sorter);
            threads[i].start();
        }

        System.out.println("\nПотоки запущены. Вводите строки (пустая строка - вывод состояния, STOP - завершение):");

        while (true) {
            String input = scanner.nextLine();
            if (input.equals("STOP")) {
                System.out.println("Получена команда STOP. Останавливаем потоки...");
                break;
            }
            else if (input.isEmpty()) {
                System.out.println("Текущее состояние списка: " + list);
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

        for (ListSorter sorter : sorters) {
            sorter.stopSorting();
        }

        for (int i = 0; i < threadCount; i++) {
            threads[i].join();
        }

        System.out.println("Финальный список: " + list);
        scanner.close();
    }
}

class ListNode implements Comparable<ListNode> {
    private final String value;
    private ListNode next;
    private final ReentrantLock lock = new ReentrantLock();

    public ListNode(String value) {
        this.value = value;
        this.next = null;
    }

    public String getValue() { return value; }

    public ListNode getNext() { return next; }
    public void setNext(ListNode next) { this.next = next; }

    public void lock() { lock.lock(); }
    public void unlock() { lock.unlock(); }

    @Override
    public int compareTo(ListNode other) {
        return this.value.compareTo(other.value);
    }
}

class MySyncList implements Iterable<String> {
    private ListNode head;
    private final ReentrantLock startLock = new ReentrantLock();

    public MySyncList() {
        this.head = new ListNode("");
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        Iterator<String> iterator = iterator();
        while (iterator.hasNext()) {
            sb.append(iterator.next());
            if (iterator.hasNext()) {
                sb.append(" -> ");
            }
        }
        sb.append("<END>");
        return sb.toString();
    }

    public void addFirst(String value) {
        startLock.lock();
        try {
            ListNode newNode = new ListNode(value);
            newNode.setNext(head);
            head = newNode;
        } finally {
            startLock.unlock();
        }
    }

    @Override
    public Iterator<String> iterator() {
        return new SyncListIterator();
    }

    private class SyncListIterator implements Iterator<String> {
        private ListNode current;

        public SyncListIterator() {
            startLock.lock();
            current = null;
        }

        @Override
        public boolean hasNext() {
            return current == null || !current.getValue().isEmpty();
        }

        @Override
        public String next() {
            if (!hasNext()) {
                throw new NoSuchElementException();
            }

            if (current == null) {
                current = head;
                if (current.getValue().isEmpty()) {
                    startLock.unlock();
                    return "";
                }
                return current.getValue();
            }

            if (current == head) {
                current.getNext().lock();
                current = current.getNext();
                startLock.unlock();
                if (current.getValue().isEmpty()) {
                    current.unlock();
                    return "";
                }
                return current.getValue();
            }

            current.getNext().lock();
            current.unlock();
            current = current.getNext();
            if (current.getValue().isEmpty()) {
                current.unlock();
                return "";
            }
            return current.getValue();
        }
    }

    public void bubbleSortIteration(int delay) throws InterruptedException {
        ListNode prev_curr, curr, next, next_next;
        startLock.lock();
        if (head.getValue().isEmpty() || head.getNext().getValue().isEmpty()) {
            startLock.unlock();
            return;
        }

        head.lock();
        head.getNext().lock();
        head.getNext().getNext().lock();
        prev_curr = null;
        curr = head;
        next = head.getNext();
        next_next = head.getNext().getNext();

        if (curr.compareTo(next) > 0) {
            swapNodes(prev_curr, curr, next, next_next);
            ListNode temp = curr;
            curr = next;
            next = temp;

            head = curr;
        }
        Thread.sleep(delay);

        if (next_next.getValue().isEmpty()) {
            curr.unlock();
            next.unlock();
            next_next.unlock();
            startLock.unlock();
            return;
        }

        prev_curr = curr;
        curr = next;
        next = next_next;
        next.getNext().lock();
        next_next = next.getNext();

        if (curr.compareTo(next) > 0) {
            swapNodes(prev_curr, curr, next, next_next);
            ListNode temp = curr;
            curr = next;
            next = temp;
        }
        Thread.sleep(delay);

        if (next_next.getValue().isEmpty()) {
            prev_curr.unlock();
            curr.unlock();
            next.unlock();
            next_next.unlock();
            startLock.unlock();
            return;
        }

        prev_curr.unlock();
        prev_curr = curr;
        curr = next;
        next = next_next;
        next.getNext().lock();
        next_next = next.getNext();
        startLock.unlock();

        do {
            if (curr.compareTo(next) > 0) {
                swapNodes(prev_curr, curr, next, next_next);
                ListNode temp = curr;
                curr = next;
                next = temp;
            }
            Thread.sleep(delay);

            prev_curr.unlock();
            prev_curr = curr;
            curr = next;
            next = next_next;
            next_next = next.getNext();

            if (next_next != null) {
                next_next.lock();
            }
        } while (next_next != null);

        prev_curr.unlock();
        curr.unlock();
        next.unlock();
    }

    private void swapNodes(ListNode prev_curr, ListNode curr, ListNode next, ListNode next_next) {
        curr.setNext(next_next);
        next.setNext(curr);
        if (prev_curr != null) {
            prev_curr.setNext(next);
        }
    }
}

class ListSorter implements Runnable {
    private final MySyncList list;
    private final int delay;
    private boolean running = true;

    public ListSorter(MySyncList list, int delay) {
        this.list = list;
        this.delay = delay;
    }

    @Override
    public void run() {
        while (running) {
            try {
                list.bubbleSortIteration(delay);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }

            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public void stopSorting() {
        running = false;
    }
}
