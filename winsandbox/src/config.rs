//! Builder for the Windows Sandbox configuration passed to `wsb start --config`.
//!
//! This produces the same `<Configuration>` XML documented for `.wsb` files.
//! Only the commonly-used elements are modeled; extend as needed.

/// A tri-state sandbox toggle. `Default` omits the element and lets Windows
/// decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Toggle {
    Enable,
    Disable,
    Default,
}

impl Toggle {
    fn element(self, name: &str, out: &mut String) {
        let value = match self {
            Toggle::Enable => "Enable",
            Toggle::Disable => "Disable",
            Toggle::Default => return,
        };
        out.push_str(&format!("  <{name}>{value}</{name}>\n"));
    }
}

/// A host folder to map into the sandbox at boot.
#[derive(Debug, Clone)]
pub struct MappedFolder {
    pub host_folder: String,
    /// Where it appears in the guest. `None` maps it onto the guest desktop.
    pub sandbox_folder: Option<String>,
    pub read_only: bool,
}

impl MappedFolder {
    /// A read-write mapping.
    pub fn read_write(host: impl Into<String>, guest: impl Into<String>) -> Self {
        MappedFolder {
            host_folder: host.into(),
            sandbox_folder: Some(guest.into()),
            read_only: false,
        }
    }

    /// A read-only mapping.
    pub fn read_only(host: impl Into<String>, guest: impl Into<String>) -> Self {
        MappedFolder {
            host_folder: host.into(),
            sandbox_folder: Some(guest.into()),
            read_only: true,
        }
    }
}

/// Windows Sandbox configuration. Build with the setters, then hand to
/// [`crate::Sandbox::start_with`].
#[derive(Debug, Clone, Default)]
pub struct SandboxConfig {
    vgpu: Option<Toggle>,
    networking: Option<Toggle>,
    mapped_folders: Vec<MappedFolder>,
    logon_command: Option<String>,
    memory_in_mb: Option<u32>,
    audio_input: Option<Toggle>,
    video_input: Option<Toggle>,
    protected_client: Option<Toggle>,
    printer_redirection: Option<Toggle>,
    clipboard_redirection: Option<Toggle>,
}

impl SandboxConfig {
    /// A fresh, empty configuration (equivalent to sandbox defaults).
    pub fn new() -> Self {
        Self::default()
    }

    pub fn vgpu(mut self, t: Toggle) -> Self {
        self.vgpu = Some(t);
        self
    }

    pub fn networking(mut self, t: Toggle) -> Self {
        self.networking = Some(t);
        self
    }

    /// Add a mapped folder. Host folders must exist when the sandbox starts.
    pub fn map_folder(mut self, folder: MappedFolder) -> Self {
        self.mapped_folders.push(folder);
        self
    }

    /// Command run automatically once the guest desktop logs on.
    pub fn logon_command(mut self, cmd: impl Into<String>) -> Self {
        self.logon_command = Some(cmd.into());
        self
    }

    pub fn memory_mb(mut self, mb: u32) -> Self {
        self.memory_in_mb = Some(mb);
        self
    }

    pub fn audio_input(mut self, t: Toggle) -> Self {
        self.audio_input = Some(t);
        self
    }

    pub fn video_input(mut self, t: Toggle) -> Self {
        self.video_input = Some(t);
        self
    }

    pub fn protected_client(mut self, t: Toggle) -> Self {
        self.protected_client = Some(t);
        self
    }

    pub fn printer_redirection(mut self, t: Toggle) -> Self {
        self.printer_redirection = Some(t);
        self
    }

    pub fn clipboard_redirection(mut self, t: Toggle) -> Self {
        self.clipboard_redirection = Some(t);
        self
    }

    /// Render the `<Configuration>` XML document.
    pub fn to_xml(&self) -> String {
        let mut out = String::from("<Configuration>\n");

        if let Some(t) = self.vgpu {
            t.element("VGpu", &mut out);
        }
        if let Some(t) = self.networking {
            t.element("Networking", &mut out);
        }

        if !self.mapped_folders.is_empty() {
            out.push_str("  <MappedFolders>\n");
            for f in &self.mapped_folders {
                out.push_str("    <MappedFolder>\n");
                out.push_str(&format!(
                    "      <HostFolder>{}</HostFolder>\n",
                    xml_escape(&f.host_folder)
                ));
                if let Some(sb) = &f.sandbox_folder {
                    out.push_str(&format!(
                        "      <SandboxFolder>{}</SandboxFolder>\n",
                        xml_escape(sb)
                    ));
                }
                out.push_str(&format!(
                    "      <ReadOnly>{}</ReadOnly>\n",
                    if f.read_only { "true" } else { "false" }
                ));
                out.push_str("    </MappedFolder>\n");
            }
            out.push_str("  </MappedFolders>\n");
        }

        if let Some(cmd) = &self.logon_command {
            out.push_str("  <LogonCommand>\n");
            out.push_str(&format!(
                "    <Command>{}</Command>\n",
                xml_escape(cmd)
            ));
            out.push_str("  </LogonCommand>\n");
        }

        if let Some(mb) = self.memory_in_mb {
            out.push_str(&format!("  <MemoryInMB>{mb}</MemoryInMB>\n"));
        }
        if let Some(t) = self.audio_input {
            t.element("AudioInput", &mut out);
        }
        if let Some(t) = self.video_input {
            t.element("VideoInput", &mut out);
        }
        if let Some(t) = self.protected_client {
            t.element("ProtectedClient", &mut out);
        }
        if let Some(t) = self.printer_redirection {
            t.element("PrinterRedirection", &mut out);
        }
        if let Some(t) = self.clipboard_redirection {
            t.element("ClipboardRedirection", &mut out);
        }

        out.push_str("</Configuration>");
        out
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
