(ns cl-5.core
  (:gen-class))

(def config
  {:num-philosophers 5
   :think-time-ms   [50 150]
   :eat-time-ms     [30 100]
   :rounds          5})

(def restart-counter (atom 0))
(def meals-counter   (atom 0))

(defn rand-in [[lo hi]]
  (+ lo (rand-int (- hi lo))))

(defn log [& args]
  (locking *out*
    (apply println args)))

(defn make-fork [id]
  (ref {:id id :uses 0 :held-by nil}))

(defn try-acquire! [left-fork right-fork phil-id]
  (dosync
    (let [l @left-fork
          r @right-fork]
      (if (or (:held-by l) (:held-by r))
        false
        (do
          (alter left-fork  assoc :held-by phil-id)
          (alter right-fork assoc :held-by phil-id)
          true)))))

(defn acquire-forks! [left-fork right-fork phil-id]
  (loop []
    (when-not (try-acquire! left-fork right-fork phil-id)
      (swap! restart-counter inc)
      (Thread/sleep (rand-int 10))
      (recur))))

(defn try-acquire-one! [fork phil-id]
  (dosync
    (if (:held-by @fork)
      false
      (do (alter fork assoc :held-by phil-id) true))))

(defn acquire-one! [fork phil-id]
  (loop []
    (when-not (try-acquire-one! fork phil-id)
      (swap! restart-counter inc)
      (recur))))

(defn release-forks! [left-fork right-fork]
  (dosync
    (alter left-fork  #(-> % (assoc :held-by nil) (update :uses inc)))
    (alter right-fork #(-> % (assoc :held-by nil) (update :uses inc)))))

(defn release-one! [fork]
  (dosync
    (alter fork #(-> % (assoc :held-by nil) (update :uses inc)))))

(defn philosopher [id forks {:keys [think-time-ms eat-time-ms rounds]}]
  (let [n         (count forks)
        left-idx  id
        right-idx (mod (inc id) n)
        [lf rf]   (if (odd? id)
                    [(forks right-idx) (forks left-idx)]
                    [(forks left-idx)  (forks right-idx)])]
    (fn []
      (dotimes [round rounds]
        (log (format "Philosopher %d [round %d/%d]: thinking..." id (inc round) rounds))
        (Thread/sleep (rand-in think-time-ms))
        (log (format "Philosopher %d: hungry, waiting for forks..." id))
        (acquire-forks! lf rf id)
        (log (format "Philosopher %d: EATING" id))
        (Thread/sleep (rand-in eat-time-ms))
        (swap! meals-counter inc)
        (release-forks! lf rf)
        (log (format "Philosopher %d: done eating." id)))
      (log (format "Philosopher %d: finished all rounds." id)))))

(defn philosopher-livelock [id forks {:keys [think-time-ms rounds]}]
  (let [n       (count forks)
        left-f  (forks id)
        right-f (forks (mod (inc id) n))]
    (fn []
      (dotimes [_ rounds]
        (Thread/sleep (rand-in think-time-ms))
        (loop []
          (acquire-one! left-f id)
          (if (try-acquire-one! right-f id)
            :ok
            (do
              (release-one! left-f)
              (swap! restart-counter inc)
              (Thread/sleep 1)
              (recur))))
        (Thread/sleep (rand-in [30 80]))
        (swap! meals-counter inc)
        (release-forks! left-f right-f)))))

(defn run-simulation
  [{:keys [num-philosophers] :as cfg} & {:keys [livelock?]}]
  (reset! restart-counter 0)
  (reset! meals-counter   0)

  (let [forks   (mapv make-fork (range num-philosophers))
        mk-phil (if livelock? philosopher-livelock philosopher)
        threads (mapv (fn [id]
                        (Thread. ^Runnable (mk-phil id forks cfg)))
                      (range num-philosophers))]

    (log "\n======================================")
    (log (format "Dining philosophers: n=%d, rounds=%d, livelock=%s"
                 num-philosophers (:rounds cfg) (boolean livelock?)))
    (log "======================================\n")

    (let [t0 (System/currentTimeMillis)]
      (run! #(.start ^Thread %) threads)
      (run! #(.join  ^Thread %) threads)
      (let [elapsed (- (System/currentTimeMillis) t0)]
        (log "\n---------------- Results ----------------")
        (log (format "Philosophers  : %d" num-philosophers))
        (log (format "Rounds each   : %d" (:rounds cfg)))
        (log (format "Total meals   : %d" @meals-counter))
        (log (format "STM retries   : %d" @restart-counter))
        (log (format "Elapsed time  : %d ms" elapsed))
        (log "\nFork usage counts:")
        (doseq [f forks]
          (log (format "  Fork %d used %d times" (:id @f) (:uses @f))))
        (log "-----------------------------------------\n")
        {:elapsed  elapsed
         :restarts @restart-counter
         :meals    @meals-counter
         :forks    (mapv deref forks)}))))

(defn -main [& args]
  (run-simulation config)

;;   (run-simulation (assoc config :num-philosophers 4))

;;   (run-simulation (assoc config :num-philosophers 5) :livelock? true)
)