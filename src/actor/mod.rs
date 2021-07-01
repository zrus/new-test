use tide::Request;

struct DiscoveryActor {
    command: DiscoveryCommand,
}

impl DiscoveryActor {
    fn new(command: DiscoveryCommand) -> DiscoveryActor {
        Self {command: command}
    }

    async fn handle_command(mut req: Request<()>) -> tide::Result {
        let command: DiscoveryCommand = req.body_json().await?;
        
    }
}

struct DiscoveryCommand {

}
