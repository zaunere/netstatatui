mod network;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use network::{Connection, NetworkMonitor};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
    Frame, Terminal,
};
use std::{
    error::Error,
    io,
    time::{Duration, Instant},
};

struct App {
    connections: Vec<Connection>,
    table_state: TableState,
    last_update: Instant,
    network_monitor: NetworkMonitor,
}

impl App {
    fn new() -> App {
        App {
            connections: Vec::new(),
            table_state: TableState::default(),
            last_update: Instant::now(),
            network_monitor: NetworkMonitor::new(),
        }
    }

    async fn update_connections(&mut self) {
        if let Ok(connections) = self.network_monitor.get_connections() {
            self.connections = connections;
            self.last_update = Instant::now();
        }
    }

    fn next(&mut self) {
        let i = match self.table_state.selected() {
            Some(i) => {
                if i >= self.connections.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn previous(&mut self) {
        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.connections.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app and run it
    let app = App::new();
    let res = run_app(&mut terminal, app).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err)
    }

    Ok(())
}

async fn run_app<B: Backend>(terminal: &mut Terminal<B>, mut app: App) -> io::Result<()> {
    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_millis(250);
    let update_rate = Duration::from_secs(1);

    // Initial data load
    app.update_connections().await;

    loop {
        terminal.draw(|f| ui(f, &mut app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Down | KeyCode::Char('j') => app.next(),
                    KeyCode::Up | KeyCode::Char('k') => app.previous(),
                    _ => {}
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }

        // Update connections periodically
        if app.last_update.elapsed() >= update_rate {
            app.update_connections().await;
        }
    }
}

fn ui(f: &mut Frame, app: &mut App) {
    // Split screen into two panels
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(f.area());

    // Separate listening and active connections
    let listening_connections: Vec<&Connection> = app.connections
        .iter()
        .filter(|conn| conn.state == "LISTEN" || conn.state.is_empty())
        .collect();

    let active_connections: Vec<&Connection> = app.connections
        .iter()
        .filter(|conn| conn.state != "LISTEN" && !conn.state.is_empty())
        .collect();

    // Render listening connections panel
    render_connections_table(
        f,
        main_chunks[0],
        &listening_connections,
        "Listening Ports",
        &mut app.table_state,
        false,
    );

    // Render active connections panel
    render_connections_table(
        f,
        main_chunks[1],
        &active_connections,
        "Active Connections",
        &mut app.table_state,
        true,
    );
}

fn render_connections_table(
    f: &mut Frame,
    area: ratatui::layout::Rect,
    connections: &[&Connection],
    title: &str,
    _table_state: &mut TableState,
    show_foreign: bool,
) {
    let header_cells: Vec<Cell> = if !show_foreign {
        ["Proto", "Local Address", "PID/Program"]
            .iter()
            .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
            .collect()
    } else {
        ["Proto", "Local Address", "Foreign Address", "State", "PID/Program"]
            .iter()
            .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
            .collect()
    };
    
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    let rows = connections.iter().map(|conn| {
        let local_addr = if conn.local_port > 0 {
            format!("{}:{}", conn.local_address, conn.local_port)
        } else {
            conn.local_address.clone()
        };

        let remote_addr = if conn.remote_port > 0 {
            format!("{}:{}", conn.remote_address, conn.remote_port)
        } else if conn.remote_address == "0.0.0.0" || conn.remote_address == "::" {
            "*:*".to_string()
        } else {
            conn.remote_address.clone()
        };

        let state = if conn.state.is_empty() {
            "-".to_string()
        } else {
            conn.state.clone()
        };

        let pid_program = match (&conn.pid, &conn.process_name) {
            (Some(pid), Some(name)) => format!("{}/{}", pid, name),
            (Some(pid), None) => format!("{}/unknown", pid),
            (None, Some(name)) => format!("-/{}", name),
            (None, None) => "-".to_string(),
        };

        let style = match conn.state.as_str() {
            "LISTEN" => Style::default().fg(Color::Green),
            "ESTABLISHED" => Style::default().fg(Color::Cyan),
            "TIME_WAIT" => Style::default().fg(Color::Yellow),
            "CLOSE_WAIT" => Style::default().fg(Color::Red),
            _ => Style::default().fg(Color::White),
        };

        if !show_foreign {
            Row::new(vec![
                Cell::from(conn.protocol.clone()),
                Cell::from(local_addr),
                Cell::from(pid_program),
            ]).style(style)
        } else {
            Row::new(vec![
                Cell::from(conn.protocol.clone()),
                Cell::from(local_addr),
                Cell::from(remote_addr),
                Cell::from(state),
                Cell::from(pid_program),
            ]).style(style)
        }
    });

    let widths = if !show_foreign {
        [
            Constraint::Length(6),  // Proto
            Constraint::Length(30), // Local Address
            Constraint::Min(25),    // PID/Program
        ].as_ref()
    } else {
        [
            Constraint::Length(6),  // Proto
            Constraint::Length(22), // Local Address
            Constraint::Length(22), // Foreign Address
            Constraint::Length(12), // State
            Constraint::Min(18),    // PID/Program
        ].as_ref()
    };

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(
                    " {} - {} connections (Press 'q' to quit) ",
                    title,
                    connections.len()
                ))
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD)
        );

    f.render_widget(table, area);
}
