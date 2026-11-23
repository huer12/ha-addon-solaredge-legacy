from dataclasses import dataclass
from statistics import median

UNDERPERFORMING_PERCENT = 85
# Below this median the day was too dark for a meaningful comparison (1 Wh resolution, noisy ratios).
MIN_MEDIAN_WH = 10


@dataclass(frozen=True)
class DailyCheck:
    relative_yield: dict[str, float | None]
    underperforming: dict[str, float]
    missing: list[str]


def evaluate(energy_today: dict[str, int], known: set[str]) -> DailyCheck | None:
    """Compare each optimizer's energy today with the median of all optimizers that reported today."""
    if not energy_today:
        return None
    mid = median(energy_today.values())
    if mid < MIN_MEDIAN_WH:
        return None
    relative = {opt_id: round(energy_today[opt_id] / mid * 100, 1) if opt_id in energy_today else None
                for opt_id in sorted(known | energy_today.keys())}
    underperforming = {opt_id: pct for opt_id, pct in relative.items()
                       if pct is not None and pct < UNDERPERFORMING_PERCENT}
    missing = sorted(known - energy_today.keys())
    return DailyCheck(relative, underperforming, missing)
