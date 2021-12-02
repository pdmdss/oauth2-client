const path = require('path');

module.exports = {
    mode: 'production',
    entry: path.resolve(__dirname, 'web.ts'),
    output: {
        path: path.resolve(__dirname, `dist`),
        filename: `web.js`
    },
    resolve: {
        extensions: ['.ts', '.js'],
        alias: {
            '@': path.resolve(__dirname, 'src')
        }
    },
    target: 'web',
    module: {
        rules: [
            {
                test: /\.ts$/,
                use: {
                    loader: 'ts-loader',
                    options: {
                        configFile: path.resolve(__dirname, 'tsconfig.json')
                    }
                }
            }
        ]
    }
};
