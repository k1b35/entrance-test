"""Воспроизводимый расчёт экономики из docs/product.md.

Цифры в продуктовом документе не должны быть «примерно посчитаны в уме»: любой
пересмотр допущения обязан пересчитывать таблицу целиком. Запуск:

    python scripts/economics.py

Все входные величины — из блока «Бизнес-вводные для расчётов» условия задачи и из
допущений A1–A8 в docs/product.md. Ни одно число здесь не подобрано под желаемый ответ.
"""

from __future__ import annotations

from dataclasses import dataclass

# --- вводные задания ---
WORKDAYS = 247                 # A1
PASSES_PER_DAY = 19_000
PEAK_PASSES = 4_275            # A2: 22.5% потока
QUEUE_WAIT_SEC = 90
CARD_PASS_SEC = 6
FACE_PASS_SEC = 2              # A3
EMPLOYEE_MIN_RUB = 10.0
GUARD_MIN_RUB = 30.0           # 120 ₽ за 4 минуты
MANUAL_CASES_TODAY = 40
RESIDUAL_MANUAL_CASES = 10     # гости, отказ турникета — не уходят никуда
CARD_REISSUE_RUB, CARDS_PER_YEAR = 250, 300
FALSE_ACCEPT_RUB = 500_000     # A5

# --- затраты ---
CAPEX_PER_GATE = 150_000 + 30_000   # edge-узел + IR-камера
GATES = 3
CAPEX_YEARS = 3
OPEX_YEAR = 480_000
TEAM_YEAR = 1_800_000               # A7: 0.5 FTE

# --- разбор одной карточки manual_review (A6) ---
GUARD_REVIEW_SEC = 30
EMPLOYEE_RETRY_SEC = 60


def rub_per_year(seconds_per_day: float, minute_rate: float) -> float:
    return seconds_per_day / 60 * minute_rate * WORKDAYS


QUEUE_TOTAL = rub_per_year(PEAK_PASSES * QUEUE_WAIT_SEC, EMPLOYEE_MIN_RUB)
PASS_TOTAL = rub_per_year(PASSES_PER_DAY * (CARD_PASS_SEC - FACE_PASS_SEC), EMPLOYEE_MIN_RUB)
FIXED_COST = CAPEX_PER_GATE * GATES / CAPEX_YEARS + OPEX_YEAR + TEAM_YEAR


@dataclass
class Scenario:
    name: str
    adoption: float      # A8
    queue_cut: float     # A4
    frr: float
    error_budget: int    # подтверждённых mis-identification в год

    def rejects_per_day(self) -> float:
        return PASSES_PER_DAY * self.frr * self.adoption

    def guard_delta(self) -> float:
        """Знак важнее величины: при высоком FRR охрана нагружается, а не разгружается."""
        cost_per_reject = GUARD_REVIEW_SEC / 60 * GUARD_MIN_RUB + EMPLOYEE_RETRY_SEC / 60 * EMPLOYEE_MIN_RUB
        after = RESIDUAL_MANUAL_CASES * 120 + self.rejects_per_day() * cost_per_reject
        before = MANUAL_CASES_TODAY * 120
        return (before - after) * WORKDAYS

    def parts(self) -> dict[str, float]:
        return {
            "проход": PASS_TOTAL * self.adoption,
            "очередь": QUEUE_TOTAL * self.queue_cut * self.adoption,
            "охрана": self.guard_delta(),
            "карты": CARD_REISSUE_RUB * CARDS_PER_YEAR * self.adoption * 0.60,
            "ошибки": -self.error_budget * FALSE_ACCEPT_RUB,
            "затраты": -FIXED_COST,
        }

    def net(self) -> float:
        return sum(self.parts().values())


SCENARIOS = [
    Scenario("пессимистичный", 0.60, 0.30, 0.020, 3),
    Scenario("базовый", 0.85, 0.60, 0.010, 2),
    Scenario("оптимистичный", 0.95, 0.75, 0.005, 1),
]


def breakeven(base: Scenario, field: str, lo: float, hi: float) -> float | None:
    """Точка, где чистый эффект обращается в ноль.

    Дихотомия, не полагающаяся на направление монотонности: если на концах отрезка
    знак одинаков, корня внутри нет и функция честно возвращает None, а не границу.
    """
    def net_at(x: float) -> float:
        return Scenario(**{**base.__dict__, field: x}).net()

    f_lo, f_hi = net_at(lo), net_at(hi)
    if f_lo == 0:
        return lo
    if f_hi == 0:
        return hi
    if (f_lo > 0) == (f_hi > 0):
        return None  # на всём допустимом диапазоне знак не меняется

    for _ in range(80):
        mid = (lo + hi) / 2
        if (net_at(mid) > 0) == (f_lo > 0):
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def main() -> None:
    print(f"Полная стоимость очереди в пике : {QUEUE_TOTAL:>14,.0f} ₽/год")
    print(f"Потенциал экономии на проходе   : {PASS_TOTAL:>14,.0f} ₽/год")
    print(f"Постоянные затраты              : {FIXED_COST:>14,.0f} ₽/год\n")

    header = f"{'сценарий':<15}" + "".join(f"{k:>13}" for k in SCENARIOS[0].parts()) + f"{'ИТОГО':>15}"
    print(header); print("-" * len(header))
    for s in SCENARIOS:
        row = f"{s.name:<15}" + "".join(f"{v:>13,.0f}" for v in s.parts().values())
        print(row + f"{s.net():>15,.0f}")

    base = SCENARIOS[1]
    print("\nТочки безубыточности (остальные параметры базовые):")
    for field, lo, hi, label in [("frr", 0.0, 0.5, "FRR"),
                                 ("adoption", 0.0, 1.0, "adoption"),
                                 ("queue_cut", 0.0, 1.0, "сокращение очереди")]:
        point = breakeven(base, field, lo, hi)
        print(f"  {label:<19}: " + (f"{point:.1%}" if point is not None else "нет в допустимом диапазоне"))

    print("\nЧувствительность от базового сценария:")
    for field, delta, label in [("frr", 0.01, "1 п.п. FRR"),
                                ("adoption", -0.10, "10 п.п. adoption"),
                                ("queue_cut", -0.10, "10 п.п. сокращения очереди")]:
        probe = Scenario(**{**base.__dict__, field: getattr(base, field) + delta})
        print(f"  {label:<28}: {base.net() - probe.net():>12,.0f} ₽/год")


if __name__ == "__main__":
    main()
