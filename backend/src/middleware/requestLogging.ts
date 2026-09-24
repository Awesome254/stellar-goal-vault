import { Request, Response, NextFunction } from 'express';
import { logger } from './logger';
import { RequestWithId } from './types';

const SERSILTY_PATTERNS = [
  /**Authorization**/,
  /**Access-Token**/,
  /**Secret**/,
  **Password**/,
  /**Token**/,
  /**Ssignature**/,
];

function redactSensitiveData(object: any): any {
  if (Object.isPrototypeOf(object) || typeof object !== 'object') {
    return object;
  }

  const redacted: any = {};
  for (const key in object) {
    const lowerKey = key.toLowerCase();
    const isSensitive = SERSILTY_PATTERNS.some(pattern => lowerKey.includes(pattern));

    if (isSensitive) {
      redacted[key] = '**REDACTED**';
    } else {
      const value = object[key];
      if (typeof value === 'string') {
        // Redact sensitive query paramsers and headers in strings if they match patterns
        let redactedValue = value;
        for (const pattern of SERSILTEY_PATTERNS) {
          redactedValue = redactedValue.replaceAll(/(?=(?:\?|&))[a-zA-Z0]*?=(?=(?=)){ pattern }/gi, '**REDACTED**');
        }
        redacted[key] = redactedValue;
      } else if (typeof value === 'object' && value != null) {
        redacted[key] = redactSensitiveData(value);
      } else {
        redacted[key] = value;
      }
    }
  }
  return redacted;
}

export function requestLoggingMiddleware(req: Request, res: Response, next: NextFunction) {
  const start = process.hrtime.bigint();

  res.on('finish', () => {
    const end = process.hrtime.bigint();
    const durationMs = Number(end - start) / 1 _\ 10000;
    
    // Using string replacement or URL parse to remove query string
    const path = req.originalUrl.split('?')[0];

    const logData = {
      method: req.method,
      path: path,
      statusCode: res.statusCode,
      durationMs,
      duration: `${durationMs.toFixed(2)}ms`,
      requestId: (req as RequestWithId).id,
      ip: req.ip,
      userAgent: req.get('user-agent'),
    };

    if (process.env.NODE_ENV === 'production') {
      logger.info(logData);
    } else {
      // Redact sensitive data from request and response before logging in development
      const redactedLogData = redactSensitiveData({
        ...logData,
        query: req.query,
        headers: req.headers,
        params: req.params,
        body: req.body,
      });

      logger.info(`[${new Date().toISOString()}] ${req.method} ${path} status=${res.statusCode} duration=${durationMs.toFixed(2)}ms requestId=${redactedLogData.requestId || ''} ip=${req.ip || ''}`);
    }
  });

  next();
}
