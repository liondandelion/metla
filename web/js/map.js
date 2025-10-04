let protocol = new pmtiles.Protocol({metadata: true});
maplibregl.addProtocol("pmtiles", protocol.tile);

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
});

function onZoom(e) {
    document.getElementById("zoomNum").innerHTML = map.getZoom().toFixed(2);
}

map.on("zoom", (e) => {
    onZoom(e);
});

map.on("load", (e) => {
    onZoom(e);
});

