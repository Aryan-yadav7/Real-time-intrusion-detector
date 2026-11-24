from ids import auth
from ids.ratelimit import RateLimiter


def test_password_hash_is_salted_and_verifies():
    h1, h2 = auth.hash_password("correct horse battery"), auth.hash_password("correct horse battery")
    assert h1 != h2                                   # random salt each time
    assert h1.startswith("scrypt$") and "correct horse" not in h1
    assert auth.verify_password("correct horse battery", h1)
    assert not auth.verify_password("correct horse batterY", h1)


def test_malformed_stored_hashes_never_verify_or_crash():
    for bad in ["", "garbage", "scrypt$1$2", "md5$1$2$3$aa$bb", "scrypt$x$8$1$zz$zz", "a$b$c$d$e$f"]:
        assert auth.verify_password("anything", bad) is False


def test_dummy_hash_is_a_real_hash():
    assert auth.verify_password("not it", auth.dummy_hash()) is False


def test_password_rules():
    assert auth.validate_password("short") is not None
    assert auth.validate_password("x" * 129) is not None
    assert auth.validate_password("password123") is not None
    assert auth.validate_password("a perfectly fine passphrase") is None


def test_email_validation():
    for good in ["a@example.com", "first.last+tag@sub.example.org"]:
        assert auth.validate_email(good)
    for bad in ["", "no-at-sign", "a@b", "a b@example.com", "a@@example.com", "@example.com",
                "x" * 300 + "@example.com"]:
        assert not auth.validate_email(bad)


def test_api_keys_are_random_and_only_hashes_are_derived():
    k1, prefix, h1 = auth.new_api_key()
    k2, _, h2 = auth.new_api_key()
    assert k1 != k2 and h1 != h2
    assert k1.startswith("sk_") and k1.startswith(prefix) and len(k1) > 40
    assert h1 == auth.sha256_hex(k1) and k1 not in h1


def test_tokens_are_unique():
    assert len({auth.new_token() for _ in range(200)}) == 200


# ---------------------------------------------------------- rate limiter
def test_rate_limiter_allows_then_blocks_then_recovers():
    now = [0.0]
    rl = RateLimiter(3, 60, clock=lambda: now[0])
    assert [rl.hit("k") for _ in range(5)] == [True, True, True, False, False]
    assert 1 <= rl.retry_after("k") <= 60
    now[0] = 61
    assert rl.hit("k") is True


def test_rate_limiter_keys_are_independent_and_denied_hits_do_not_extend_the_lockout():
    now = [0.0]
    rl = RateLimiter(2, 10, clock=lambda: now[0])
    rl.hit("a"); rl.hit("a")
    for t in (1, 2, 3, 4, 5):
        now[0] = t
        assert rl.hit("a") is False        # hammering...
    assert rl.hit("b") is True              # other keys unaffected
    now[0] = 10.5
    assert rl.hit("a") is True              # ...did not push the end of the lockout out


def test_rate_limiter_memory_is_bounded():
    now = [0.0]
    rl = RateLimiter(1, 5, clock=lambda: now[0], max_keys=100)
    for i in range(150):
        rl.hit(f"k{i}")
    now[0] = 100
    rl.hit("trigger")
    for i in range(150):
        rl.hit(f"z{i}")
    assert len(rl._hits) <= 260
