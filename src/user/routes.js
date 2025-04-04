const express = require('express');

const routes = express.Router({
    mergeParams: true
});

routes.get('/', (req, res) => {
    res.status(200).json({user: `Hello user ${req.body.userId}!`});
});

module.exports = {
    routes,
};

