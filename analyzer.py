# from typing import Tuple, List

# from utils.safe_browsing import check_safe_browsing
# from concurrent.futures import ThreadPoolExecutor, as_completed

# from checker.url_checker import (
#     check_https,
#     check_short_domain,
#     check_contains_suspicious_words,
#     check_safe_browsing_status
# )

# def rate_site(url: str) -> Tuple[str, List[str], str]:
#     score = 0
#     reasons = []

#     checks = [
#         ("https", check_https),
#         ("short_domain", check_short_domain),
#         ("suspicious_words", check_contains_suspicious_words),
#         ("safe_browsing", check_safe_browsing_status)
#     ]

#     with ThreadPoolExecutor(max_workers=4) as executor:
#         futures = {
#             executor.submit(func, url): name
#             for name, func in checks
#         }

#         for future in as_completed(futures):
#             task_name = futures[future]
#             result = future.result()

#             if task_name == 'https' and not result:
#                 score += 1
#                 reasons.append("Não utiliza HTTPS")

#             elif task_name == 'short_domain' and result:
#                 score += 1
#                 reasons.append("Domínio muito curto")

#             elif task_name == 'suspicious_words' and result:
#                 score += 1
#                 reasons.append("Contém palavras suspeitas")

#             elif task_name == 'safe_browsing':
#                 suspect, reason_sb = result
#                 if suspect:
#                     score += 1
#                     reasons.append(reason_sb)

#     if score == 0:
#         return "✅ Provavelmente legítimo", reasons, "green"
#     elif score == 1:
#         return "⚠️ Potencialmente suspeito", reasons, "yellow"
#     else:
#         return "❌ Alta suspeita de site fraudulento", reasons, "red"