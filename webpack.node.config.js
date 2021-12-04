const path = require('path');
const fs = require('fs');

const nodeModules = {};
fs.readdirSync('node_modules')
    .filter(x => ['.bin'].indexOf(x) === -1)
    .forEach(mod => nodeModules[mod] = 'commonjs ' + mod);


module.exports = {
    mode: 'production',
    entry: path.resolve(__dirname, 'index.ts'),
    output: {
        path: path.resolve(__dirname, 'dist'),
        filename: 'node.js'
    },
    resolve: {
        extensions: ['.ts']
    },
    target: 'node',
    module: {
        rules: [
            {
                test: /\.ts$/,
                exclude: /node_modules/,
                use: {
                    loader: 'ts-loader',
                    options: {
                        configFile: path.resolve(__dirname, 'tsconfig.json')
                    }
                }
            }
        ]
    },
    externals: nodeModules
};
