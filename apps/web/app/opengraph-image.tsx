import { ImageResponse } from 'next/og';

export const runtime = 'edge';

// Image metadata
export const alt = `Opengraph Image`;
export const size = {
  width: 800,
  height: 400,
};

export const contentType = 'image/png';

export default async function Image() {
  return new ImageResponse(
    (
      <div
        style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          fontSize: 24,
          fontWeight: 600,
          textAlign: 'left',
          padding: 70,
          color: 'red',
          backgroundImage: 'linear-gradient(to right, #334d50, #cbcaa5)',
          height: '100%',
          width: '100%',
        }}
      >
        Hello World
      </div>
    ),
    {
      ...size,
    },
  );
}
