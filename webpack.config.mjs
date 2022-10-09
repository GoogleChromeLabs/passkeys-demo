import sass from 'sass';

export default {
  entry: {
    'components-bundle': './public/components.js',
    'styles-bundle': './public/style.scss',
  },
  mode: 'production',
  output: {
    filename: '[name].js',
  },
  module: {
    rules: [
      {
        test: /\.scss$/,
        use: [
          {
            loader: 'file-loader',
            options: {
              name: 'bundle.css',
            },
          },
          { loader: 'extract-loader' },
          { loader: 'css-loader' },
          {
            loader: 'sass-loader',
            options: {
              implementation: sass,
              webpackImporter: false,
              sassOptions: {
                includePaths: ['./node_modules'],
              },
            },
          },
        ],
      },
      {
        test: /components\.js$/,
        loader: 'babel-loader',
        query: { presets: ['env'] },
      },
    ],
  },
};
