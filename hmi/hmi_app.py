import dash
from dash import dcc, html, Input, Output, State
import dash_bootstrap_components as dbc
from pymodbus.client import ModbusTcpClient
import os
import plotly.graph_objs as go
from collections import deque
import datetime

# Config
PLC_IP = os.environ.get('PLC_IP', 'plc_simulator')
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.CYBORG])

# Historical data for charts
MAX_POINTS = 60
times = deque(maxlen=MAX_POINTS)
pressures = deque(maxlen=MAX_POINTS)
flows = deque(maxlen=MAX_POINTS)
temps = deque(maxlen=MAX_POINTS)

def get_plc_data():
    """Connect fresh each time to avoid stale socket issues."""
    client = ModbusTcpClient(PLC_IP, port=502)
    try:
        if client.connect():
            # Read registers 100-103: pressure, flow*10, temp, pump_rpm
            res = client.read_holding_registers(100, 4)
            if hasattr(res, 'registers') and not res.isError():
                pressure = float(res.registers[0])
                flow = float(res.registers[1]) / 10.0
                temp = float(res.registers[2])
                pump_rpm = float(res.registers[3])
                return pressure, flow, temp, pump_rpm
    except Exception as e:
        print(f"Modbus read error: {e}")
    finally:
        try:
            client.close()
        except Exception:
            pass
    return 0.0, 0.0, 0.0, 0.0

app.layout = dbc.Container([
    dbc.Row([
        dbc.Col(html.H1("Purdue Level 2 – ICS Pipeline HMI",
                        className="text-center text-primary mb-2"), width=12)
    ]),
    dbc.Row([
        dbc.Col(html.P("Live Siemens S7/Modbus Process Control Dashboard",
                       className="text-center text-muted mb-4"), width=12)
    ]),

    # ── Controls ──────────────────────────────────────────────────────────────
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("⚙️ Process Control"),
                dbc.CardBody([
                    html.Label("Pump RPM", className="fw-bold"),
                    dcc.Slider(0, 3000, 100, value=1200, id='pump-slider', className="text-muted",
                               marks={0: '0', 1000: '1k', 2000: '2k', 3000: '3k'},
                               tooltip={"placement": "bottom", "always_visible": True}),
                    html.Hr(),
                    html.Label("Main Valve", className="fw-bold"),
                    dbc.Button("Toggle Valve", id="valve-btn", color="success",
                               className="w-100 mt-1"),
                    html.Div(id="valve-status", children="🔴 Valve: CLOSED",
                             className="mt-2 text-center fw-bold"),
                    html.Hr(),
                    dbc.Card([
                        dbc.CardBody([
                            html.Small("Pump RPM", className="text-muted"),
                            html.H4("0", id="rpm-display", className="text-center text-white"),
                        ])
                    ], className="mb-2"),
                    dbc.Card([
                        dbc.CardBody([
                            html.Small("Temperature (°C)", className="text-muted"),
                            html.H4("0.0", id="temp-display", className="text-center text-danger"),
                        ])
                    ]),
                ])
            ], className="mb-4 h-100")
        ], width=3),

        # ── Live readings ──────────────────────────────────────────────────────
        dbc.Col([
            dbc.Row([
                dbc.Col(dbc.Card([
                    dbc.CardHeader("🔵 Pressure (PSI)"),
                    dbc.CardBody(html.H2("0.0", id="pressure-display",
                                         className="text-center text-info"))
                ]), width=6),
                dbc.Col(dbc.Card([
                    dbc.CardHeader("🟡 Flow Rate (L/s)"),
                    dbc.CardBody(html.H2("0.0", id="flow-display",
                                         className="text-center text-warning"))
                ]), width=6),
            ], className="mb-4"),

            dbc.Card([
                dbc.CardHeader("📈 Telemetry History"),
                dbc.CardBody(dcc.Graph(id='live-graph',
                                       config={'displayModeBar': False},
                                       style={'height': '350px'}))
            ])
        ], width=9)
    ]),

    dcc.Interval(id='interval-component', interval=2000, n_intervals=0),
    dcc.Store(id='valve-state-store', data=0)
], fluid=True)


# ── Telemetry update callback ──────────────────────────────────────────────────
@app.callback(
    [Output('pressure-display', 'children'),
     Output('flow-display', 'children'),
     Output('live-graph', 'figure'),
     Output('valve-status', 'children'),
     Output('valve-btn', 'color'),
     Output('temp-display', 'children'),
     Output('rpm-display', 'children')],
    [Input('interval-component', 'n_intervals')],
    [State('valve-state-store', 'data')]
)
def update_metrics(n, valve_state):
    pressure, flow, temp, pump_rpm = get_plc_data()

    now = datetime.datetime.now()
    times.append(now)
    pressures.append(pressure)
    flows.append(flow)
    temps.append(temp)

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=list(times), y=list(pressures),
        name='Pressure (PSI)', line=dict(color='#17a2b8', width=2),
        fill='tozeroy', fillcolor='rgba(23,162,184,0.1)'
    ))
    fig.add_trace(go.Scatter(
        x=list(times), y=list(flows),
        name='Flow (L/s)', line=dict(color='#ffc107', width=2),
        yaxis='y2'
    ))
    fig.update_layout(
        template='plotly_dark',
        margin=dict(l=40, r=40, t=10, b=40),
        yaxis=dict(title='Pressure (PSI)', rangemode='tozero'),
        yaxis2=dict(title='Flow (L/s)', overlaying='y', side='right', rangemode='tozero'),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        hovermode='x unified'
    )

    valve_text = "🟢 Valve: OPEN" if valve_state == 1 else "🔴 Valve: CLOSED"
    valve_color = "success" if valve_state == 1 else "danger"

    return (f"{pressure:.1f}", f"{flow:.2f}", fig,
            valve_text, valve_color,
            f"{temp:.1f}", f"{int(pump_rpm)}")


# ── Valve toggle callback ──────────────────────────────────────────────────────
@app.callback(
    Output('valve-state-store', 'data'),
    [Input('valve-btn', 'n_clicks')],
    [State('valve-state-store', 'data')]
)
def toggle_valve(n, current_state):
    if n is None:
        return current_state
    new_state = 1 if current_state == 0 else 0
    client = ModbusTcpClient(PLC_IP, port=502)
    try:
        if client.connect():
            # Write to register 202 (valve on/off)
            client.write_register(202, new_state)
    except Exception as e:
        print(f"Valve write error: {e}")
    finally:
        try:
            client.close()
        except Exception:
            pass
    return new_state


# ── Pump RPM callback ──────────────────────────────────────────────────────────
@app.callback(
    Output('valve-status', 'className'),  # dummy output
    Input('pump-slider', 'value'),
    prevent_initial_call=True
)
def set_pump_rpm(value):
    client = ModbusTcpClient(PLC_IP, port=502)
    try:
        if client.connect():
            client.write_register(200, int(value))
    except Exception as e:
        print(f"Pump write error: {e}")
    finally:
        try:
            client.close()
        except Exception:
            pass
    return "mt-2 text-center fw-bold"


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8060, debug=False)
