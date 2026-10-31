use crate::nfqws2::plan::{Plan, QueueNum};

/// Всё, что файрвол должен знать о плане: очередь и порт. Метки правила берут из
/// раскладки процесса (`nfqws2::mark`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dispatch {
    pub queue: QueueNum,
    pub dport: u16,
}

impl Plan {
    pub fn dispatch(&self, dport: u16) -> Dispatch {
        Dispatch {
            queue: self.queue(),
            dport,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfqws2::plan::{FilterMark, Plan, QueueNum};

    fn dispatch_of() -> Dispatch {
        let strategies = vec![vec!["--a".to_string()]];
        Plan::from_strategies(&FilterMark::granted(), QueueNum::new(200), &strategies).dispatch(443)
    }

    #[test]
    fn dispatch_carries_queue_and_port() {
        let d = dispatch_of();
        assert_eq!(d.queue.get(), 200);
        assert_eq!(d.dport, 443);
    }
}
