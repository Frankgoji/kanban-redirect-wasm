module.exports = (env) => {
    env = env || {};
    const debug = !!env.debug;
    console.log(`Debug mode: ${debug}`);
    console.log(`minify: ${!debug}`);
    const options = {
        minify: !debug,
        jsc: {
            parser: {
                syntax: 'ecmascript',
                jsx: true,
                dynamicImport: true
            }
        }
    };
    console.log(JSON.stringify(options, null, 2));
    return {
        mode: debug ? 'development' : 'production',
        entry: {
            'kanban-redirect': __dirname + '/app/index.js',
        },
        experiments: {
            asyncWebAssembly: true,
        },
        module: {
            rules: [
                {
                    test: /\/app\/.*\.js$/,
                    exclude: /node_modules/,
                    use: {
                        loader: 'swc-loader',
                        options: options
                    }
                }
            ]
        },
        output: {
            filename: '[name].js',
            path: __dirname + '/build'
        }
    };
};
