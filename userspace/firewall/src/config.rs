use aya::{maps::HashMap, Bpf};
use firewall_common::{Action, ConfigOpt};

use crate::{Error, Result, CONFIG};

pub struct ConfigHandler {
    store_name: String,
}

impl ConfigHandler {
    pub fn new() -> Result<Self> {
        Self::new_with_name(CONFIG)
    }

    fn new_with_name(map_name: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            store_name: map_name.as_ref().to_string(),
        })
    }

    pub fn set_default_action(&mut self, bpf: &mut Bpf, action: Action) -> Result<()> {
        let mut store =
            HashMap::try_from(bpf.map_mut(&self.store_name).ok_or(Error::MapNotFound)?)?;
        store.insert(ConfigOpt::DefaultAction, action as i32, 0)?;
        Ok(())
    }
}
