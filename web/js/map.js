let protocol = new pmtiles.Protocol({metadata: true});
maplibregl.addProtocol("pmtiles", protocol.tile);

let mapState = {
    clickPlacesMarker: false,
    clickRemovesMarker: false,
    markerFollowsMouse: null,
    markersFromNew: [],
    markersFromEvent: [],
};

function markerPlace() {
    mapState.clickPlacesMarker = true;
    mapState.clickRemovesMarker = false;
}

function markerRemove() {
    mapState.clickRemovesMarker = true;
    mapState.clickPlacesMarker = false;
}

function markerRemoveAll(markers) {
    for (const marker of markers) {
        marker.remove()
    }
    markers = []
}

function markersFromNewRemove() {
    markerRemoveAll(mapState.markersFromNew)
}

function markersFromEventRemove() {
    markerRemoveAll(mapState.markersFromEvent)
}

function markersFromNewHide() {
    for (const marker of mapState.markersFromNew) {
        marker.remove()
    }
}

function markersFromNewUnhide() {
    for (const marker of mapState.markersFromNew) {
        marker.addTo(map)
    }
}

function onMouseLeftMap() {
    if (mapState.markerFollowsMouse !== null) {
        mapState.markerFollowsMouse.remove();
        mapState.markerFollowsMouse = null;
        mapState.clickPlacesMarker = false;
    }
}

function onZoom(e) {
    document.getElementById("zoomNum").innerHTML = map.getZoom().toFixed(2);
}

function markersFromNewToGeoJSON() {
    const geojson = {
        type: "FeatureCollection",
        features: mapState.markersFromNew.map(marker => ({
            type: "Feature",
            geometry: {
                type: "Point",
                coordinates: [marker.getLngLat().lng, marker.getLngLat().lat]
            },
        }))
    };
    return geojson;
}

function markersFromNewToGeoJSONString() {
    const geojson =  markersFromNewToGeoJSON()
    return JSON.stringify(geojson)
}

function geoJSONStringToEventMarkers(stringJSON) {
    const geojson = JSON.parse(stringJSON)

    geojson.features.forEach((feature) => {
        const marker = new maplibregl.Marker()
            .setLngLat(feature.geometry.coordinates)
            .addTo(map);
        mapState.markersFromEvent.push(marker)
    });
}

var map = new maplibregl.Map({
    container: 'map', // container id
    //style: 'https://demotiles.maplibre.org/style.json', // style URL
    center: [30.113525, 59.903402], // starting position [lng, lat]
    zoom: 9, // starting zoom
    maxBounds: [29.410000, 59.615000, 30.780000, 60.265000],
    style: "assets/map/basemaps-assets/style.json",
});

map.addControl(new maplibregl.NavigationControl({
    showZoom: true,
    showCompass: false,
}));

map.addControl(new maplibregl.ScaleControl({
    maxWidth: 100,
    unit: "metric",
}), "top-right");

map.on("click", (e) => {
    const features = map.queryRenderedFeatures(e.point);

    // Limit the number of properties we're displaying for
    // legibility and performance
    const displayProperties = [
        "type",
        "properties",
        "id",
        "layer",
        "source",
        "sourceLayer",
        "state",
    ];

    const displayFeatures = features.map((feat) => {
        const displayFeat = {};
        displayProperties.forEach((prop) => {
            displayFeat[prop] = feat[prop];
        });
        return displayFeat;
    });

    document.getElementById("features").innerHTML = JSON.stringify(
        displayFeatures,
        null,
        2,
    );

    const lngLat = e.lngLat;

    if (mapState.clickPlacesMarker) {
        const marker = new maplibregl.Marker()
            .setLngLat(lngLat)
            .addTo(map);

        marker.getElement().addEventListener("click", () => {
            if (mapState.clickRemovesMarker) {
                mapState.markersFromNew = mapState.markersFromNew.filter(m => m !== marker);
                marker.remove();
                mapState.clickRemovesMarker = false;
            }
        });

        mapState.markersFromNew.push(marker);

        mapState.clickPlacesMarker = false;
        if (mapState.markerFollowsMouse !== null) {
            mapState.markerFollowsMouse.remove()
            mapState.markerFollowsMouse = null;
        }
    }
});

map.on("zoom", (e) => {
    onZoom(e);
});

map.on("load", (e) => {
    onZoom(e);
});

map.on("mousemove", (e) => {
    if (mapState.clickPlacesMarker) {
        const lngLat = e.lngLat;
        if (mapState.markerFollowsMouse === null) {
            mapState.markerFollowsMouse = new maplibregl.Marker()
            .setLngLat(lngLat)
            .addTo(map);
        } else mapState.markerFollowsMouse.setLngLat(lngLat);
    }
});
