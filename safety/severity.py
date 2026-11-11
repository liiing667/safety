from collections.abc import Mapping
from typing import Any, Dict, List, Optional

UNKNOWN_SEVERITY = "unknown"


def cvssv3_base_score_from_data(cvssv3: Any) -> Optional[float]:
    """
    Gets a usable CVSSv3 base score from CVSSv3 data.

    Args:
        cvssv3 (Any): The CVSSv3 data.

    Returns:
        Optional[float]: The base score, or None if it is unavailable or invalid.
    """
    if not isinstance(cvssv3, Mapping):
        return None

    base_score = cvssv3.get("base_score")
    if base_score is None or isinstance(base_score, bool):
        return None

    try:
        score = float(base_score)
    except (TypeError, ValueError):
        return None

    if not 0.0 <= score <= 10.0:
        return None

    return score


def cvssv3_base_score(vuln: Dict[str, Any]) -> Optional[float]:
    """
    Gets a usable CVSSv3 base score from a vulnerability.

    A vulnerability can have severity data without having CVSSv3 data (for
    example, when only CVSSv2 information is available). That is an unknown
    CVSSv3 severity, not a critical one.

    Args:
        vuln (Dict[str, Any]): The vulnerability.

    Returns:
        Optional[float]: The CVSSv3 base score, or None if it is unavailable.
    """
    severity = vuln.get("severity")
    if not isinstance(severity, Mapping):
        return None

    return cvssv3_base_score_from_data(severity.get("cvssv3"))


def highest_base_score(vulns: List[Dict[str, Any]]) -> Optional[float]:
    """
    Calculates the highest usable CVSSv3 base score from vulnerabilities.

    Args:
        vulns (List[Dict[str, Any]]): The vulnerabilities.

    Returns:
        Optional[float]: The highest usable CVSSv3 base score, or None when no
        vulnerability has one.
    """
    scores = [score for vuln in vulns if (score := cvssv3_base_score(vuln)) is not None]
    return max(scores) if scores else None


def severity_meets_threshold(vulns: List[Dict[str, Any]], threshold: float) -> bool:
    """
    Checks whether a set of vulnerabilities meets a CVSSv3 severity threshold.

    Only real CVSSv3 base scores are compared with the threshold. Unknown
    scores must not be treated as critical. If every vulnerability has an
    unknown score, the numeric threshold cannot exclude them; in that case
    the result stays unknown and is handled by the unknown-severity setting.

    Args:
        vulns (List[Dict[str, Any]]): The vulnerabilities.
        threshold (float): The minimum CVSSv3 base score.

    Returns:
        bool: True if the vulnerabilities meet the threshold.
    """
    scores = [score for vuln in vulns if (score := cvssv3_base_score(vuln)) is not None]

    if not scores:
        return True

    return any(score >= threshold for score in scores)


def all_severities_unknown(vulns: List[Dict[str, Any]]) -> bool:
    """
    Checks whether every vulnerability has an unknown CVSSv3 severity.

    Args:
        vulns (List[Dict[str, Any]]): The vulnerabilities.

    Returns:
        bool: True if no vulnerability has a usable CVSSv3 base score.
    """
    return not any(cvssv3_base_score(vuln) is not None for vuln in vulns)


def cvss3_score_to_label(score: Optional[float]) -> Optional[str]:
    """
    Converts a CVSS v3 score to a severity label.

    Args:
        score (Optional[float]): The CVSS v3 score. None means the score is
            unknown.

    Returns:
        Optional[str]: The severity label, "unknown" when the score is
        unavailable, or None when the score is invalid.
    """
    if score is None:
        return UNKNOWN_SEVERITY
    elif 0.1 <= score <= 3.9:
        return "low"
    elif 4.0 <= score <= 6.9:
        return "medium"
    elif 7.0 <= score <= 8.9:
        return "high"
    elif 9.0 <= score <= 10.0:
        return "critical"

    return None
