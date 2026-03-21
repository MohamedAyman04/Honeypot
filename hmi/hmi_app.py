import dash
from dash import dcc, html, Input, Output, State
import dash_bootstrap_components as dbc
from pymodbus.client import ModbusTcpClient
import os
import plotly.graph_objs as go
from collections import deque

# Config
PLC_IP = os.environ.get('PLC_IP', 'plc_simulator')
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.CYBORG])

# Historical data for charts
MAX_POINTS = 50
times = deque(maxlen=MAX_POINTS)
pressures = deque(maxlen=MAX_POINTS)
flows = deque(maxlen=MAX_POINTS)

app.layout = dbc.Container([
    dbc.Row([
        dbc.Col(html.H1("Purdue Level 2 - Oil Pipeline HMI", className="text-center text-primary mb-4"), width=12)
    ]),
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Process Control"),
                dbc.CardBody([
                    html.Label("Pump RPM"),
                    dcc.Slider(0, 3000, 100, value=0, id='pump-slider', marks={0: '0', 3000: '3000'}),
                    html.Hr(),
                    html.Label("Main Valve"),
                    dbc.Button("Toggle Valve", id="valve-btn", color="success", className="w-100"),
                    html.Div(id="valve-status", children="Closed", className="mt-2 text-center")
                ])
            ], className="mb-4")
        ], width=4),
        dbc.Col([
            dbc.Row([
                dbc.Col(dbc.Card([
                    dbc.CardHeader("Pressure (PSI)"),
                    dbc.CardBody(html.H2("0.0", id="pressure-display", className="text-center text-info"))
                ]), width=6),
                dbc.Col(dbc.Card([
                    dbc.CardHeader("Flow Rate (L/s)"),
                    dbc.CardBody(html.H2("0.0", id="flow-display", className="text-center text-warning"))
                ]), width=6),
            ], className="mb-4"),
            dbc.Card([
                dbc.CardHeader("Telemetry History"),
                dbc.CardBody(dcc.Graph(id='live-graph', config={'displayModeBar': False}))
            ])
        ], width=8)
    ]),
    dcc.Interval(id='interval-component', interval=2000, n_intervals=0),
    dcc.Store(id='valve-state-store', data=0)
], fluid=True)

@app.callback(
    [Output('pressure-display', 'children'),
     Output('flow-display', 'children'),
     Output('live-graph', 'figure'),
     Output('valve-status', 'children'),
     Output('valve-btn', 'color')],
    [Input('interval-component', 'n_intervals')],
    [State('valve-state-store', 'data')]
)
def update_metrics(n, valve_state):
    client = ModbusTcpClient(PLC_IP, port=5020)
    pressure = 0.0
    flow = 0.0
    
    try:
        if client.connect():
            # Read sensors (100, 101)
            res = client.read_holding_registers(100, 2)
            if not res.isError():
                pressure = float(res.registers[0])
                flow = float(res.registers[1]) / 10.0
            client.close()
    except:
        pass

    import datetime
    now = datetime.datetime.now()
    times.append(now)
    pressures.append(pressure)
    flows.append(flow)

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=list(times), y=list(pressures), name='Pressure', line=dict(color='#17a2b8')))
    fig.add_trace(go.Scatter(x=list(times), y=list(flows), name='Flow', line=dict(color='#ffc107'), yaxis='y2'))
    
    fig.update_layout(
        template='plotly_dark',
        margin=dict(l=20, r=20, t=20, b=20),
        yaxis=dict(title='Pressure (PSI)'),
        yaxis2=dict(title='Flow (L/s)', overlaying='y', side='right'),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
    )

    valve_text = "Valve: OPEN" if valve_state == 1 else "Valve: CLOSED"
    valve_color = "success" if valve_state == 1 else "danger"

    return f"{pressure:.1f}", f"{flow:.2f}", fig, valve_text, valve_color

@app.callback(
    Output('valve-state-store', 'data'),
    [Input('valve-btn', 'n_clicks')],
    [State('valve-state-store', 'data')]
)
def toggle_valve(n, current_state):
    if n is None: return current_state
    new_state = 1 if current_state == 0 else 0
    client = ModbusTcpClient(PLC_IP, port=5020)
    try:
        if client.connect():
            client.write_register(201, new_state)
            client.close()
    except:
        pass
    return new_state

@app.callback(
    Output('valve-status', 'className'),   # dummy output, any existing element works
    Input('pump-slider', 'value'),
    prevent_initial_call=True
)
def set_pump_rpm(value):
    client = ModbusTcpClient(PLC_IP, port=5020)
    try:
        if client.connect():
            client.write_register(200, value)
            client.close()
    except:
        pass
    return "mt-2 text-center"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8060, debug=False)
