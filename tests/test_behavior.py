from ids.behavior import BehaviorConfig, BehaviorTracker, extract_username


def tracker(**overrides):
    return BehaviorTracker(BehaviorConfig(**overrides))


def kinds(findings):
    return {f.category for f in findings}


# ---------------------------------------------------------------- flood
def test_flood_fires_on_the_threshold_request_only():
    t = tracker(flood_requests=100, flood_window=10)
    results = [t.on_request("1.1.1.1", now=i * 0.01) for i in range(100)]
    assert all(r == [] for r in results[:99])
    assert kinds(results[99]) == {"flood"}


def test_slow_traffic_is_not_a_flood():
    t = tracker(flood_requests=100, flood_window=10)
    assert all(t.on_request("1.1.1.1", now=i * 0.5) == [] for i in range(300))  # 2 per second


def test_flood_alerts_once_per_cooldown_then_again():
    t = tracker(flood_requests=10, flood_window=10, cooldown=60)
    fired = [bool(t.on_request("1.1.1.1", now=i * 0.01)) for i in range(50)]
    assert fired.count(True) == 1
    later = 100.0  # cooldown over, flood still going
    again = [bool(t.on_request("1.1.1.1", now=later + i * 0.01)) for i in range(20)]
    assert again.count(True) == 1


def test_different_ips_are_counted_separately():
    t = tracker(flood_requests=10, flood_window=10)
    for i in range(9):
        assert t.on_request("1.1.1.1", now=i * 0.01) == []
        assert t.on_request("2.2.2.2", now=i * 0.01) == []


# ---------------------------------------------------------- brute force
def failed_login(t, ip="1.1.1.1", user="alice", now=0.0, path="/login", status=401, method="POST"):
    return t.on_response(ip, method, path, status, username=user, now=now)


def test_brute_force_fires_on_the_fifth_failure():
    t = tracker(brute_failures=5)
    results = [failed_login(t, now=i) for i in range(5)]
    assert all(r == [] for r in results[:4])
    assert kinds(results[4]) == {"brute_force"}


def test_failures_spread_over_time_do_not_add_up():
    t = tracker(brute_failures=5, brute_window=60)
    assert all(failed_login(t, now=i * 30) == [] for i in range(20))


def test_only_failed_posts_to_login_paths_count():
    t = tracker(brute_failures=3)
    for i in range(10):
        assert failed_login(t, now=i, status=200) == []            # success
        assert failed_login(t, now=i, path="/search") == []        # not a login path
        assert failed_login(t, now=i, method="GET") == []          # not a POST
    assert t.active_offenses("1.1.1.1", now=11) == {}


def test_login_path_matching_ignores_case_and_trailing_slash():
    t = tracker(brute_failures=3)
    assert t.is_login_path("/Login/") and t.is_login_path("/wp-login.php")
    assert not t.is_login_path("/loginfo")


# ---------------------------------------------------- credential stuffing
def test_many_usernames_is_stuffing_not_brute_force():
    t = tracker(brute_failures=5, stuffing_usernames=5)
    results = [failed_login(t, user=f"user{i}", now=i) for i in range(5)]
    assert kinds(results[4]) == {"credential_stuffing"}
    assert not any("brute_force" in kinds(r) for r in results)


def test_stuffing_evidence_never_contains_usernames():
    t = tracker(stuffing_usernames=3)
    results = [failed_login(t, user=f"secretname{i}", now=i) for i in range(3)]
    evidence = results[2][0].evidence
    assert "secretname" not in evidence and "3" in evidence


def test_same_username_case_differences_count_once():
    t = tracker(stuffing_usernames=3, brute_failures=100)
    for i, name in enumerate(["Alice", "alice", "ALICE ", "alice"]):
        assert failed_login(t, user=name, now=i) == []


# -------------------------------------------------------------- scanning
def test_scanning_needs_many_different_missing_paths():
    t = tracker(scan_paths=15)
    results = [t.on_response("1.1.1.1", "GET", f"/nope{i}", 404, now=i) for i in range(15)]
    assert all(r == [] for r in results[:14])
    assert kinds(results[14]) == {"scanning"}


def test_same_missing_page_repeated_is_not_scanning():
    t = tracker(scan_paths=5)
    assert all(t.on_response("1.1.1.1", "GET", "/old-page", 404, now=i) == [] for i in range(50))


def test_sensitive_probes_count_even_when_not_404():
    t = tracker(scan_paths=3)
    out = [t.on_response("1.1.1.1", "GET", p, 200, probe=True, now=i)
           for i, p in enumerate(["/.env", "/.git/config", "/wp-admin"])]
    assert kinds(out[2]) == {"scanning"}


# -------------------------------------------------- active alerts / expiry
def test_active_offenses_expire_after_cooldown():
    t = tracker(brute_failures=2, cooldown=60)
    failed_login(t, now=0)
    failed_login(t, now=1)
    assert t.active_offenses("1.1.1.1", now=2) == {"brute_force": 75}
    assert 55 <= t.retry_after("1.1.1.1", now=2) <= 61
    assert t.active_offenses("1.1.1.1", now=62) == {}
    assert t.retry_after("1.1.1.1", now=62) == 0
    assert t.active_offenses("9.9.9.9", now=2) == {}


# ---------------------------------------------------------------- memory
def test_memory_stays_bounded():
    t = tracker(max_tracked_ips=100)
    for i in range(5000):
        t.on_request(f"10.0.{i // 250}.{i % 250}", now=i * 0.001)
    assert len(t._states) <= 100 + 500  # trimmed at the next housekeeping pass


def test_quiet_ips_are_forgotten():
    t = tracker()
    for i in range(10):
        t.on_request(f"10.0.0.{i}", now=0)
    for i in range(500):
        t.on_request("5.5.5.5", now=1000 + i)
    assert set(t._states) == {"5.5.5.5"}


# ------------------------------------------------------ username parsing
def test_extract_username_from_json_and_form():
    assert extract_username('{"username": "bob", "password": "x"}') == "bob"
    assert extract_username('{"Email": "bob@example.com"}') == "bob@example.com"
    assert extract_username("username=bob&password=x") == "bob"
    assert extract_username("password=x") is None
    assert extract_username("") is None
    assert extract_username("[1, 2, 3]") is None
    assert extract_username('{"nested": {"username": "x"}}') is None
