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
 * @param failures  失败明细（最多保留若干条，避免刷屏）
 */
public record MigrationReport(String source, boolean dryRun, int total, int imported,
                              int skipped, int noPassword, List<String> failures) {

    public boolean hasFailures() {
        return !failures.isEmpty();
    }
}
