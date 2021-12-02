import * as oauth2 from './src';

// @ts-ignore
const DMDATA = (window ?? globalThis ?? global ?? this).DMDATA ??= {};

DMDATA.OAuth2Code = oauth2.OAuth2Code;
DMDATA.SubWindowMode = oauth2.SubWindowMode;
