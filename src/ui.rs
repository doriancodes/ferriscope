use ratatui::{
    backend::CrosstermBackend,
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    layout::{Layout, Constraint, Direction},
    Terminal,
    style::{Style, Color},
};
use crossterm::{
    event::{self, Event, KeyCode},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    execute,
};
use std::error::Error;
use tokio::sync::mpsc;
use std::io::stdout;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct App {
    terminal: Terminal<CrosstermBackend<std::io::Stdout>>,
    packets: Vec<PacketInfo>,
    selected: Option<usize>,
    packet_rx: mpsc::Receiver<PacketInfo>,
    running: Arc<AtomicBool>,
}

#[derive(Clone)]
pub struct PacketInfo {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub length: usize,
    pub info: String,
    pub raw_data: Vec<u8>,
}

impl App {
    pub fn new(packet_rx: mpsc::Receiver<PacketInfo>) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let mut stdout = stdout();
        execute!(stdout, EnterAlternateScreen)?;
        enable_raw_mode()?;

        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        let running = Arc::new(AtomicBool::new(true));

        // Set up Ctrl+C handler
        let running_handler = running.clone();
        ctrlc::set_handler(move || {
            running_handler.store(false, Ordering::SeqCst);
        })?;

        Ok(Self {
            terminal,
            packets: Vec::new(),
            selected: None,
            packet_rx,
            running,
        })
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        while self.running.load(Ordering::SeqCst) {
            // Check for new packets
            while let Ok(packet) = self.packet_rx.try_recv() {
                self.packets.push(packet);
            }

            // Draw UI
            self.draw()?;

            // Handle input with timeout
            if event::poll(std::time::Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Up => self.select_previous(),
                        KeyCode::Down => self.select_next(),
                        _ => {}
                    }
                }
            }
        }

        // Cleanup
        self.cleanup()?;
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        disable_raw_mode()?;
        execute!(self.terminal.backend_mut(), LeaveAlternateScreen)?;
        self.terminal.show_cursor()?;
        Ok(())
    }

    fn draw(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.terminal.draw(|frame| {
            let size = frame.area();
            
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Percentage(70),
                    Constraint::Percentage(30),
                ].as_ref())
                .split(size);

            // Packet list
            let items: Vec<ListItem> = self.packets
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    let style = if Some(i) == self.selected {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default()
                    };
                    
                    ListItem::new(format!(
                        "{} {} {} -> {} [{}] {}",
                        p.timestamp.format("%H:%M:%S%.3f"),
                        p.protocol,
                        p.source,
                        p.destination,
                        p.length,
                        p.info
                    )).style(style)
                })
                .collect();

            let list = List::new(items)
                .block(Block::default()
                    .title("Network Packets")
                    .borders(Borders::ALL))
                .highlight_style(Style::default().fg(Color::Yellow));

            frame.render_widget(list, chunks[0]);

            // Packet details
            if let Some(selected) = self.selected {
                if let Some(packet) = self.packets.get(selected) {
                    let details = vec![
                        format!("Timestamp: {}", packet.timestamp),
                        format!("Protocol: {}", packet.protocol),
                        format!("Source: {}", packet.source),
                        format!("Destination: {}", packet.destination),
                        format!("Length: {} bytes", packet.length),
                        format!("Info: {}", packet.info),
                        String::new(),
                        "Raw Data (hex):".to_string(),
                        format_hex_dump(&packet.raw_data),
                    ].join("\n");

                    let details_widget = Paragraph::new(details)
                        .block(Block::default()
                            .title("Packet Details")
                            .borders(Borders::ALL))
                        .wrap(Wrap { trim: true });

                    frame.render_widget(details_widget, chunks[1]);
                }
            }
        })?;

        Ok(())
    }

    fn select_next(&mut self) {
        self.selected = match self.selected {
            Some(i) if i < self.packets.len() - 1 => Some(i + 1),
            None if !self.packets.is_empty() => Some(0),
            _ => self.selected,
        };
    }

    fn select_previous(&mut self) {
        self.selected = match self.selected {
            Some(i) if i > 0 => Some(i - 1),
            _ => self.selected,
        };
    }
}

impl Drop for App {
    fn drop(&mut self) {
        // Ensure terminal is restored even if we panic
        let _ = self.cleanup();
    }
}

fn format_hex_dump(data: &[u8]) -> String {
    let mut output = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        output.push_str(&format!("{:08x}  ", i * 16));
        
        for (j, byte) in chunk.iter().enumerate() {
            output.push_str(&format!("{:02x}", byte));
            if j % 2 == 1 {
                output.push(' ');
            }
        }
        
        // Pad with spaces if this row is shorter than 16 bytes
        for _ in chunk.len()..16 {
            output.push_str("  ");
            if chunk.len() % 2 == 0 {
                output.push(' ');
            }
        }
        
        output.push_str(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() {
                output.push(*byte as char);
            } else {
                output.push('.');
            }
        }
        output.push_str("|\n");
    }
    output
}


