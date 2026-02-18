use pecr_contracts::Budget;
use std::time::{Duration, Instant};

const UNBOUNDED_WALLCLOCK_TIMEOUT: Duration = Duration::from_secs(31_536_000_000);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BudgetStopReason {
    MaxOperatorCalls,
    MaxBytes,
    MaxWallclockMs,
    MaxRecursionDepth,
}

impl BudgetStopReason {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::MaxOperatorCalls => "budget_max_operator_calls",
            Self::MaxBytes => "budget_max_bytes",
            Self::MaxWallclockMs => "budget_max_wallclock_ms",
            Self::MaxRecursionDepth => "budget_max_recursion_depth",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct BudgetScheduler<'a> {
    budget: &'a Budget,
    started_at: Instant,
}

impl<'a> BudgetScheduler<'a> {
    pub(super) fn new(budget: &'a Budget, started_at: Instant) -> Self {
        Self { budget, started_at }
    }

    pub(super) fn effective_parallelism(self) -> usize {
        self.budget.max_parallelism.unwrap_or(1).max(1) as usize
    }

    pub(super) fn adaptive_parallelism(
        self,
        operator_calls_used: u32,
        reserved_calls: u32,
    ) -> usize {
        let base = self.effective_parallelism();
        let used_with_reserved = operator_calls_used.saturating_add(reserved_calls);
        let remaining_calls = self
            .budget
            .max_operator_calls
            .saturating_sub(used_with_reserved);
        let call_budget_cap = remaining_calls.max(1) as usize;

        let wallclock_cap = match self.remaining_wallclock() {
            None => 1,
            Some(remaining) => {
                let ms = remaining.as_millis();
                if ms < 100 {
                    1
                } else if ms < 500 {
                    2
                } else if ms < 2_000 {
                    4
                } else {
                    base
                }
            }
        };

        base.min(call_budget_cap).min(wallclock_cap).max(1)
    }

    pub(super) fn remaining_wallclock(self) -> Option<Duration> {
        remaining_wallclock(self.budget, self.started_at)
    }

    pub(super) fn check_depth(self, depth_used: u32) -> Result<(), BudgetStopReason> {
        if depth_used >= self.budget.max_recursion_depth {
            return Err(BudgetStopReason::MaxRecursionDepth);
        }
        Ok(())
    }

    pub(super) fn check_operator_calls(self, used: u32) -> Result<(), BudgetStopReason> {
        if used >= self.budget.max_operator_calls {
            return Err(BudgetStopReason::MaxOperatorCalls);
        }
        Ok(())
    }

    pub(super) fn check_operator_calls_with_reserved(
        self,
        used: u32,
        reserved: u32,
    ) -> Result<(), BudgetStopReason> {
        if used.saturating_add(reserved) >= self.budget.max_operator_calls {
            return Err(BudgetStopReason::MaxOperatorCalls);
        }
        Ok(())
    }

    pub(super) fn check_bytes(self, used: u64) -> Result<(), BudgetStopReason> {
        if used > self.budget.max_bytes {
            return Err(BudgetStopReason::MaxBytes);
        }
        Ok(())
    }
}

pub(super) fn remaining_wallclock(budget: &Budget, started_at: Instant) -> Option<Duration> {
    if budget.max_wallclock_ms == 0 {
        return Some(UNBOUNDED_WALLCLOCK_TIMEOUT);
    }

    let elapsed_ms = started_at.elapsed().as_millis() as u64;
    if elapsed_ms >= budget.max_wallclock_ms {
        return None;
    }

    Some(Duration::from_millis(
        budget.max_wallclock_ms.saturating_sub(elapsed_ms),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_budget() -> Budget {
        Budget {
            max_operator_calls: 5,
            max_bytes: 1024,
            max_wallclock_ms: 1000,
            max_recursion_depth: 3,
            max_parallelism: Some(4),
        }
    }

    #[test]
    fn scheduler_checks_calls_depth_bytes_and_parallelism() {
        let budget = sample_budget();
        let scheduler = BudgetScheduler::new(&budget, Instant::now());

        assert_eq!(scheduler.effective_parallelism(), 4);
        assert!(scheduler.check_operator_calls(4).is_ok());
        assert_eq!(
            scheduler.check_operator_calls(5),
            Err(BudgetStopReason::MaxOperatorCalls)
        );
        assert!(scheduler.check_operator_calls_with_reserved(3, 1).is_ok());
        assert_eq!(
            scheduler.check_operator_calls_with_reserved(4, 1),
            Err(BudgetStopReason::MaxOperatorCalls)
        );

        assert!(scheduler.check_depth(2).is_ok());
        assert_eq!(
            scheduler.check_depth(3),
            Err(BudgetStopReason::MaxRecursionDepth)
        );

        assert!(scheduler.check_bytes(1024).is_ok());
        assert_eq!(scheduler.check_bytes(1025), Err(BudgetStopReason::MaxBytes));
    }

    #[test]
    fn scheduler_remaining_wallclock_is_unbounded_when_zero_limit() {
        let mut budget = sample_budget();
        budget.max_wallclock_ms = 0;
        let scheduler = BudgetScheduler::new(&budget, Instant::now());
        let remaining = scheduler
            .remaining_wallclock()
            .expect("zero wallclock should be unbounded");
        assert!(remaining >= Duration::from_secs(60 * 60 * 24 * 365));
    }

    #[test]
    fn scheduler_remaining_wallclock_expires_after_limit() {
        let budget = sample_budget();
        let started_at = Instant::now() - Duration::from_millis(2_000);
        let scheduler = BudgetScheduler::new(&budget, started_at);
        assert!(scheduler.remaining_wallclock().is_none());
    }

    #[test]
    fn scheduler_adaptive_parallelism_caps_by_remaining_call_budget() {
        let budget = sample_budget();
        let scheduler = BudgetScheduler::new(&budget, Instant::now());

        assert_eq!(scheduler.adaptive_parallelism(0, 0), 4);
        assert_eq!(scheduler.adaptive_parallelism(4, 0), 1);
        assert_eq!(scheduler.adaptive_parallelism(3, 1), 1);
    }

    #[test]
    fn scheduler_adaptive_parallelism_degrades_with_low_wallclock() {
        let mut budget = sample_budget();
        budget.max_wallclock_ms = 200;
        let scheduler = BudgetScheduler::new(&budget, Instant::now());
        assert!(scheduler.adaptive_parallelism(0, 0) <= 2);
    }
}
