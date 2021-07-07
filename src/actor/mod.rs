use bastion::prelude::*;
use std::{thread::sleep, time::Duration};

#[derive(Debug, Clone)]
pub enum DiscoveryCommands {
    OnceScan,
    ScheduledScan,
}

impl DiscoveryCommands {
    pub fn value(&self) -> &str {
        match *self {
            DiscoveryCommands::OnceScan => "once",
            DiscoveryCommands::ScheduledScan => "scheduled",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveryActor {
    supervisor: Bastion::SupervisorRef,
    children: Bastion::ChildRef,
    callbacks: Bastion::Callbacks,
}

impl DiscoveryActor {
    pub fn new() -> Self {
        let callbacks = Callbacks::new()
            .with_before_start(move || {
                unimplemented!();
            })
            .with_after_stop(|| {
                unimplemented!();
            })
            .with_after_start(|| {
                unimplemented!();
            });

        let supervisor = Bastion::supervisor(|sp| sp.with_strategy(Supervision::OneForOne))
            .expect("Could not create supervisor");

        let children = supervisor
            .children(|c| c.with_callbacks(callbacks))
            .expect("Could not create children");

        DiscoveryActor {
            supervisor,
            children,
            callbacks,
        }
    }

    async fn add_child_task(&mut self, ctx: BastionContext) -> Result<(), ()> {
        MessageHandler::new(ctx.recv().await?)
            .on_question(|question: &str, sender| match *question {
                DiscoveryCommands::OnceScan => "once",
                DiscoveryCommands::ScheduledScan => "scheduled",
            })
            .on_fallback(|v, addr| panic!("Wrong message from {:?}: got {:?}", add, v));
        Ok(())
    }

    pub fn add_child(&mut self) -> Self {}

    pub fn start(&mut self) {
        supervisor
            .children(move |children| {
                children
                    .with_distributor(Distributor::named("discovery-actor"))
                    .with_exec(|ctx: BastionContext| {
                        println!("a child is running");
                    })
                    .with_callbacks(callbacks)
            })
            .expect("Could not create a children group");
    }
}

#[cfg(test)]
pub mod test {
    #[test]
    pub fn test() {}
}
