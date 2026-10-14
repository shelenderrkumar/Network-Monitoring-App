import pytest

from dpiguard.policy import DomainPolicy, matches, normalize


def test_rules_cover_subdomains_but_not_lookalikes():
    assert matches("youtube.com", "youtube.com")
    assert matches("youtube.com", "www.youtube.com")
    assert not matches("youtube.com", "notyoutube.com")
    assert normalize("*.YouTube.com.") == "youtube.com"


def test_observe_decides_with_most_specific_rule():
    policy = DomainPolicy(["example.com", "api.example.com"])
    assert policy.observe("v1.api.example.com", "1.1.1.1").rule == "api.example.com"
    assert policy.observe("www.example.com", "1.1.1.2").rule == "example.com"
    assert not policy.observe("other.org", "1.1.1.3").block


def test_adding_a_rule_blocks_already_observed_ips():
    policy = DomainPolicy()
    policy.observe("www.youtube.com", "10.0.0.2")
    policy.observe("i.ytimg.com", "10.0.0.9")
    assert policy.add_rule("youtube.com") == {"10.0.0.2"}


def test_unblock_removes_exactly_the_ips_no_rule_needs():
    policy = DomainPolicy(["a.com", "b.com"])
    policy.observe("a.com", "10.0.0.1")
    policy.observe("b.com", "10.0.0.1")  # same IP serves both blocked domains
    policy.observe("a.com", "10.0.0.2")
    assert policy.remove_rule("a.com") == {"10.0.0.2"}  # 10.0.0.1 still needed by b.com
    assert policy.remove_rule("b.com") == {"10.0.0.1"}


def test_collateral_reports_allowed_domains_on_blocked_ips():
    policy = DomainPolicy(["blocked.com"])
    policy.observe("blocked.com", "10.0.0.5")
    policy.observe("innocent.org", "10.0.0.5")  # shared hosting / CDN
    assert policy.collateral() == {"10.0.0.5": ["innocent.org"]}


@pytest.mark.parametrize("bad", ["", "  ", "two words.com"])
def test_invalid_rules_are_rejected(bad):
    with pytest.raises(ValueError):
        DomainPolicy().add_rule(bad)
