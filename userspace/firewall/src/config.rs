use aya::{
    maps::{HashMap, MapRefMut},
    Bpf,
};
use firewall_common::{Action, ConfigOpt};

use crate::{Result, CONFIG};

pub struct ConfigHandler {
    ebpf_map: HashMap<MapRefMut, ConfigOpt, i32>,
}

impl ConfigHandler {
    pub fn new(bpf: &Bpf) -> Result<Self> {
        Self::new_with_name(bpf, CONFIG)
    }

    fn new_with_name(bpf: &Bpf, map_name: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            ebpf_map: HashMap::try_from(bpf.map_mut(map_name.as_ref())?)?,
        })
    }

    pub fn set_default_action(&mut self, action: Action) -> Result<()> {
        self.ebpf_map
            .insert(ConfigOpt::DefaultAction, action as i32, 0)?;
        Ok(())
    }
}
