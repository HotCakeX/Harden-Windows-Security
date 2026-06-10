#define D2D_INPUT_COUNT 1
#define D2D_INPUT0_SIMPLE
#define D2D_REQUIRES_SCENE_POSITION

#include "d2d1effecthelpers.hlsli"

float t;
float2 r;

float2 MyTanh(float2 x)
{
    float2 ex = exp(x);
    float2 emx = exp(-x);
    return (ex - emx) / (ex + emx);
}

float2 MultiplyByImageMatrix(float2 value)
{
    return float2(value.x - value.y, value.x + value.y);
}

float2 MultiplyByForegroundMatrix(float2 value, float2 d, float denom)
{
    return float2(value.x + value.y, value.x * d.x / denom + value.y * d.y / denom);
}

float2 MultiplyByTimeMatrix(float2 value, float baseAngle)
{
    float m00 = cos(baseAngle + 0.0);
    float m01 = cos(baseAngle + 33.0);
    float m10 = cos(baseAngle + 11.0);
    float m11 = cos(baseAngle + 0.0);
    return float2(value.x * m00 + value.y * m01, value.x * m10 + value.y * m11);
}

D2D_PS_ENTRY(main)
{
    float2 fragCoord = D2DGetScenePosition().xy;
    float4 o_bg = float4(0.0, 0.0, 0.0, 0.0);
    float4 o_anim = float4(0.0, 0.0, 0.0, 0.0);

    {
        float2 p_img = (fragCoord * 2.0 - r) / r.y;
        p_img = MultiplyByImageMatrix(p_img);
        float2 l_val = MyTanh(p_img * 5.0 + 2.0);
        l_val = min(l_val, l_val * 3.0);
        float2 clamped = clamp(l_val, -2.0, 0.0);
        float diff_y = clamped.y - l_val.y;
        float safe_px = abs(p_img.x) < 0.001 ? 0.001 : p_img.x;
        float term = (0.1 - max(0.01 - dot(p_img, p_img) / 200.0, 0.0) * (diff_y / safe_px)) / abs(length(p_img) - 0.7);
        o_bg += float4(term, term, term, term);
        o_bg *= max(o_bg, float4(0.0, 0.0, 0.0, 0.0));
    }

    {
        float2 p_anim = (fragCoord * 2.0 - r) / r.y / 0.7;
        float2 d = float2(-1.0, 1.0);
        float denom = 0.1 + 5.0 / dot(5.0 * p_anim - d, 5.0 * p_anim - d);
        float2 c = MultiplyByForegroundMatrix(p_anim, d, denom);
        float2 v = c;
        float safeLength = max(length(v), 0.0001);
        float baseAngle = log(safeLength) + t * 0.2;
        v = MultiplyByTimeMatrix(v, baseAngle) * 5.0;
        float4 animAccum = float4(0.0, 0.0, 0.0, 0.0);

        for (int i = 1; i <= 9; i++)
        {
            float fi = (float)i;
            animAccum += sin(float4(v.x, v.y, v.y, v.x)) + float4(1.0, 1.0, 1.0, 1.0);
            v += 0.7 * sin(float2(v.y, v.x) * fi + t) / fi + 0.5;
        }

        float4 expTerm = exp(c.x * float4(0.6, -0.4, -1.0, 0.0));
        float2 sinInput = sin(v / 0.3) * 0.2 + c * float2(1.0, 2.0);
        float ringTerm = 0.1 + 0.1 * pow(length(sinInput) - 1.0, 2.0);
        float gravityTerm = 1.0 + 7.0 * exp(0.3 * c.y - dot(c, c));
        float edgeTerm = 0.03 + abs(length(p_anim) - 0.7);
        float4 animTerm = 1.0 - exp(-expTerm / animAccum / ringTerm / gravityTerm / edgeTerm * 0.2);
        o_anim += animTerm;
    }

    float4 finalColor = lerp(o_bg, o_anim, 0.5) * 1.5;
    finalColor = clamp(finalColor, 0.0, 1.0);
    return finalColor;
}
