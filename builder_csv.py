import concurrent
from features.features import (
    check_contains_suspicious_words,
    check_days_to_expiration,
    check_domain_age_days,
    check_domain_in_rbl,
    check_domain_is_ip,
    check_double_slash_redirect,
    check_has_at_symbol,
    check_https,
    check_hyphen_in_domain,
    check_indexed_by_google,
    check_ip_from_trusted_country,
    check_nonstandard_port,
    check_phishing_query_params,
    check_query_params_count,
    check_redirect_count,
    check_response_time_ms,
    check_safe_browsing_status,
    check_short_domain,
    check_subdomain_count,
    check_url_shortener,
)


def get_url_features(url: str) -> dict:
    funcs = {
        "uses_https": check_https,
        "short_domain": check_short_domain,
        "has_suspicious_words": check_contains_suspicious_words,
        "safe_browsing": check_safe_browsing_status,
        "redirect_count": check_redirect_count,
        "listed_in_rbl": check_domain_in_rbl,
        "ip_country": check_ip_from_trusted_country,
        "indexed_by_google": check_indexed_by_google,
        "domain_age_days": check_domain_age_days,
        "domain_days_to_expiration": check_days_to_expiration,
        "is_ip_domain": check_domain_is_ip,
        "has_at_symbol": check_has_at_symbol,
        "has_double_slash": check_double_slash_redirect,
        "has_hyphen": check_hyphen_in_domain,
        "subdomain_count": check_subdomain_count,
        "query_params_count": check_query_params_count,
        "has_phishing_query_params": check_phishing_query_params,
        "nonstandard_port": check_nonstandard_port,
        "url_shortener": check_url_shortener,
        "response_time_ms": check_response_time_ms,
    }
    results = {}

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_key = {executor.submit(func, url): key for key, func in funcs.items()}
        for future in concurrent.futures.as_completed(future_to_key):
            key = future_to_key[future]
            try:
                res = future.result()
                if isinstance(res, (bool)):
                    res = int(res)
                elif isinstance(res, (list, tuple)):
                    res = int(res[0]) if res else 0
                results[key] = res
            except Exception as e:
                results[key] = -1

    return results
