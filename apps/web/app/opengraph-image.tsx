import { ImageResponse } from 'next/og';

export const runtime = 'edge';

// Image metadata
export const alt = 'Turborepo Opengraph Image';
export const size = {
  width: 800,
  height: 400,
};

export const contentType = 'image/png';

const OpengraphImage = async () =>
  new ImageResponse(
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
        <img
          src={`https://www.aungpyaephyo.com/og-logo.png`}
          alt="opengraph logo"
          style={{
            width: '400px',
            height: '400px',
            borderRadius: '50%',
            objectFit: 'cover',
          }}
        />
      </div>
    ),
    {
      ...size,
    },
  );

export default OpengraphImage;
