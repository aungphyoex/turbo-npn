import { ImageResponse } from 'next/og';
import { NextRequest } from 'next/server';

export const runtime = 'edge';

export async function GET(req: NextRequest) {
  const { searchParams } = req.nextUrl;
  const title = searchParams.get('title');
  const description = searchParams.get('description');
  const font = fetch(new URL('./mono.ttf', import.meta.url)).then((res) =>
    res.arrayBuffer(),
  );
  const fontData = await font;

  return new ImageResponse(
    (
      <div
        style={{
          display: 'flex',
          height: '100%',
          width: '100%',
          backgroundColor: 'black',
          color: 'white',
          fontFamily: 'Geist Sans',
          position: 'relative',
        }}
      >
        <div
          style={{
            display: 'flex',
            position: 'absolute',
            borderLeft: '1px dashed #4b5563',
            top: 0,
            bottom: 0,
            left: '4rem',
            width: '1px',
          }}
        />
        <div
          style={{
            display: 'flex',
            position: 'absolute',
            borderLeft: '1px dashed #4b5563',
            top: 0,
            bottom: 0,
            right: '4rem',
            width: '1px',
          }}
        />
        <div
          style={{
            display: 'flex',
            position: 'absolute',
            borderTop: '1px solid #4b5563',
            left: 0,
            right: 0,
            top: '4rem',
            height: '1px',
          }}
        />
        <div
          style={{
            display: 'flex',
            position: 'absolute',
            borderTop: '1px solid #4b5563',
            left: 0,
            right: 0,
            bottom: '4rem',
            height: '1px',
          }}
        />
        <div
          style={{
            display: 'flex',
            flexDirection: 'row',
            position: 'absolute',
            bottom: '6rem',
            right: '6rem',
            color: 'white',
          }}
        />
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            position: 'absolute',
            width: '896px',
            justifyContent: 'center',
            top: '8rem',
            bottom: '8rem',
            left: '8rem',
            right: '8rem',
          }}
        >
          <div
            style={{
              flexGrow: 1,
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'center',
              lineHeight: 1.1,
              textWrap: 'balance',
              fontWeight: 600,
              fontSize: title && title.length > 20 ? '64px' : '80px',
              letterSpacing: '-0.04em',
            }}
          >
            {title ?? ''}
          </div>
          <div
            style={{
              fontSize: '40px',
              lineHeight: 1.5,
              flexGrow: 1,
              color: '#9ca3af',
              fontWeight: 500,
              textWrap: 'balance',
            }}
          >
            {description ? description?.slice(0, 100) : ''}
          </div>
        </div>
      </div>
    ),
    {
      width: 1200,
      height: 628,
      fonts: [
        {
          name: 'Jetbrains Mono',
          data: fontData,
          style: 'normal',
        },
      ],
    },
  );
}
