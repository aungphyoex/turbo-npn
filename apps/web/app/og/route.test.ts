import { NextRequest } from 'next/server';
import { describe, expect, it } from 'vitest';
import { GET } from './route';

describe('OG Image Route', () => {
  it('Returns a valid ImageResponse', async () => {
    // Mock NextRequest with title and description params
    const url = new URL(
      'http://localhost/api/og?title=Test+Title&description=Test+Desc',
    );
    const req = {
      nextUrl: url,
    } as unknown as NextRequest;

    const res = await GET(req);

    expect(res).toBeInstanceOf(Response); // or ImageResponse
    expect(res.headers.get('Content-Type')).toBe('image/png');
  });
});
