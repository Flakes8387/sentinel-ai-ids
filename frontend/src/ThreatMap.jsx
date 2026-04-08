import React from 'react';
import { ComposableMap, Geographies, Geography, Marker } from "react-simple-maps";

const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

const ThreatMap = ({ isCritical, alerts = [] }) => {
    // Dynamically pull genuine geolocations from the live alerts data
    // Restrict map to showing the 5 most recent unique spatial sources to prevent clutter
    const dynamicMarkers = alerts
        .filter(alert => alert.location && alert.location.lat !== undefined && alert.location.lon !== undefined)
        .slice(0, 5)
        .map((alert, idx) => ({
            id: `alert-${idx}`,
            coordinates: [alert.location.lon, alert.location.lat],
            isThreat: true
        }));

    // Retain the central defensive node (e.g. your literal server location)
    const centralNode = { id: "Current Node", coordinates: [-122.4194, 37.7749], isThreat: false };

    // Combine them, putting the threats first
    const activeMarkers = [...dynamicMarkers, centralNode];

    return (
        <div style={{ width: "100%", height: "100%", position: "relative" }}>
            <ComposableMap projectionConfig={{ scale: 140 }} style={{ width: "100%", height: "100%" }}>
                <Geographies geography={geoUrl}>
                    {({ geographies }) =>
                        geographies.map((geo) => (
                            <Geography
                                key={geo.rsmKey}
                                geography={geo}
                                fill="rgba(255, 255, 255, 0.05)"
                                stroke="rgba(255, 255, 255, 0.1)"
                                strokeWidth={0.5}
                                style={{
                                    default: { outline: "none" },
                                    hover: { fill: "rgba(255, 255, 255, 0.1)", outline: "none" },
                                    pressed: { outline: "none" },
                                }}
                            />
                        ))
                    }
                </Geographies>
                {activeMarkers.map(({ id, coordinates, isThreat }) => (
                    <Marker key={id} coordinates={coordinates}>
                        <circle
                            r={isThreat && isCritical ? 8 : 4}
                            fill={isThreat && isCritical ? "var(--critical-base)" : "var(--accent-base)"}
                            style={{
                                filter: isThreat && isCritical ? "drop-shadow(0 0 10px var(--critical-glow))" : "drop-shadow(0 0 5px var(--accent-glow))",
                                transition: "all 0.5s ease"
                            }}
                        />
                    </Marker>
                ))}
            </ComposableMap>
        </div>
    );
};

export default ThreatMap;
