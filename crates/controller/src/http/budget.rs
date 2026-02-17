use pecr_contracts::Budget;
use std::time::{Duration, Instant};

const UNBOUNDED_WALLCLOCK_TIMEOUT: Duration = Duration::from_secs(31_536_000_000);

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
