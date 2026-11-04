package cn.miku.auth.migrate;

import java.util.List;

/**
 * 迁移结果报告。
 *
 * @param source    来源插件名（展示用）
 * @param dryRun    是否为试运行（只看结果不写库）
 * @param total     源库读到的账号总数
 * @param imported  成功写入的数量
 * @param skipped   跳过的数量（账号已存在，不覆盖）
 * @param noPassword 源里没有可用密码哈希的数量（迁入后需玩家重新设置密码）
 * @param failed    因数据库错误而整批写入失败的数量（与"跳过"分开计，
 *                  否则报告口径会骗人：写失败被显示成"已存在、未覆盖"）
 * @param failures  失败明细（最多保留若干条，避免刷屏）
 */
public record MigrationReport(String source, boolean dryRun, int total, int imported,
                              int skipped, int noPassword, int failed, List<String> failures) {

    public boolean hasFailures() {
        return !failures.isEmpty();
    }
}
